"""DNS message decoding for the tunneling and DGA detectors.

Only the parts detection reads are decoded: the header flags, the question
section and the answer section's envelope. Record data is handed back as raw
bytes so this module never has to grow a decoder per record type.

Messages come off the wire, so every count and length here is attacker
controlled. Names are the dangerous part: RFC 1035 compression lets a name
point backwards, and nothing in the format stops a capture from encoding a
pointer that leads to itself, or a chain of thousands of them. Decoding caps
the jumps per name, which bounds the work a message can buy rather than only
making a loop terminate eventually.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_NULL = 10
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33
QTYPE_ANY = 255

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

HEADER_LEN = 12
MAX_NAME_LEN = 255      # whole name in wire form, length bytes and root included

# Compression jumps allowed per name. Real messages use one, occasionally two.
# The cap is what keeps cost linear in the message: without it a chain of N
# pointers costs O(N) per name and a message is O(N) names long, so a single
# 16 KB datagram of chained pointers takes seconds to parse.
MAX_POINTERS = 32

# QUERY, IQUERY, STATUS, NOTIFY, UPDATE and DSO. Every other opcode value is
# unassigned, so a payload claiming one is not DNS.
ASSIGNED_OPCODES = frozenset({0, 1, 2, 4, 5, 6})

_LABEL_NORMAL = 0x00
_LABEL_POINTER = 0xC0
_LABEL_KIND_MASK = 0xC0

ROOT = "."


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclass(frozen=True, slots=True)
class DnsMessage:
    txid: int
    is_response: bool
    opcode: int
    rcode: int
    truncated_flag: bool
    questions: tuple[DnsQuestion, ...]
    answers: tuple[DnsRecord, ...]

    @property
    def query_name(self) -> str | None:
        """The name the message is about, which is what detection keys on."""
        return self.questions[0].name if self.questions else None


def parse_dns(payload: bytes) -> DnsMessage | None:
    """Decode a UDP-borne DNS message, or None if it is not plausibly one.

    Sections are parsed for as long as the buffer holds out: a qdcount of 65535
    yields however many questions were really there, never an error and never
    65535 allocations.
    """
    if len(payload) < HEADER_LEN:
        return None

    txid, flags, qdcount, ancount = struct.unpack_from("!HHHH", payload, 0)
    opcode = (flags >> 11) & 0x0F
    if opcode not in ASSIGNED_OPCODES:
        return None

    offset = HEADER_LEN
    questions: list[DnsQuestion] = []
    for _ in range(qdcount):
        parsed = _read_question(payload, offset)
        if parsed is None:
            break
        question, offset = parsed
        questions.append(question)

    # A message that promises a question but carries nothing decodable at the
    # only fixed offset in the format is the strongest signal that this payload
    # is not DNS at all.
    if qdcount and not questions:
        return None

    answers: list[DnsRecord] = []
    if len(questions) == qdcount:
        for _ in range(ancount):
            parsed_rr = _read_record(payload, offset)
            if parsed_rr is None:
                break
            record, offset = parsed_rr
            answers.append(record)

    return DnsMessage(
        txid=txid,
        is_response=bool(flags & 0x8000),
        opcode=opcode,
        rcode=flags & 0x000F,
        truncated_flag=bool(flags & 0x0200),
        questions=tuple(questions),
        answers=tuple(answers),
    )


def parse_dns_tcp(payload: bytes) -> DnsMessage | None:
    """Decode a DNS message carried over TCP, which prefixes a 2 byte length.

    The prefix bounds the message when the segment holds more than one, but it
    cannot extend it: a message split across segments is parsed from the bytes
    actually present, since the question section leads and is what detection
    needs.
    """
    if len(payload) < 2 + HEADER_LEN:
        return None
    declared = struct.unpack_from("!H", payload, 0)[0]
    if declared < HEADER_LEN:
        return None
    return parse_dns(payload[2:2 + declared])


def _read_question(buf: bytes, offset: int) -> tuple[DnsQuestion, int] | None:
    parsed = read_name(buf, offset)
    if parsed is None:
        return None
    name, offset = parsed
    if offset + 4 > len(buf):
        return None
    qtype, qclass = struct.unpack_from("!HH", buf, offset)
    return DnsQuestion(name, qtype, qclass), offset + 4


def _read_record(buf: bytes, offset: int) -> tuple[DnsRecord, int] | None:
    parsed = read_name(buf, offset)
    if parsed is None:
        return None
    name, offset = parsed
    if offset + 10 > len(buf):
        return None
    # TTL is specified as signed but only positive values are legal, so it is
    # read unsigned and left as the wire value.
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    if offset + rdlength > len(buf):
        return None
    rdata = buf[offset:offset + rdlength]
    return DnsRecord(name, rtype, rclass, ttl, rdata), offset + rdlength


def read_name(buf: bytes, offset: int) -> tuple[str, int] | None:
    """Decode a possibly compressed name, returning it with the offset after it.

    The returned offset is the one to keep reading the message from, so for a
    compressed name it points past the first pointer rather than past whatever
    the pointer led to.

    None means the name is unusable: a truncated buffer, a reserved label type,
    a pointer out of the message, a name over the RFC limits, or more than
    MAX_POINTERS jumps, which is what a self-referential or cyclic chain hits.
    """
    labels: list[str] = []
    wire_len = 1                # the root label is always there to pay for
    jumps = 0
    end = -1
    pos = offset

    while True:
        if pos >= len(buf):
            return None
        length = buf[pos]
        kind = length & _LABEL_KIND_MASK

        if kind == _LABEL_NORMAL:
            # A normal label carries its length in the low 6 bits, so RFC
            # 1035's 63 byte label limit holds by construction here.
            pos += 1
            if length == 0:
                break
            wire_len += 1 + length
            if wire_len > MAX_NAME_LEN or pos + length > len(buf):
                return None
            labels.append(buf[pos:pos + length].decode("latin-1").lower())
            pos += length
        elif kind == _LABEL_POINTER:
            if pos + 2 > len(buf):
                return None
            target = ((length & 0x3F) << 8) | buf[pos + 1]
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > MAX_POINTERS or target >= len(buf):
                return None
            pos = target
        else:
            # 0b01 and 0b10 were the extended label types, withdrawn by
            # RFC 6891; nothing on a real network sends them.
            return None

    if end < 0:
        end = pos
    return (".".join(labels) if labels else ROOT), end
