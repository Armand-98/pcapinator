"""DNS parser tests built from hand-assembled bytes.

Every message is assembled field by field from RFC 1035, so a passing test
means the parser agrees with the specification rather than with itself. The
hostile cases are the point of the file: compression loops, lying counts,
oversized names and reserved label types all have to end in None.
"""

import random
import struct
import time

import pytest

from pcapinator.layers.dns import (
    HEADER_LEN,
    MAX_NAME_LEN,
    MAX_POINTERS,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_ANY,
    QTYPE_CNAME,
    QTYPE_MX,
    QTYPE_NS,
    QTYPE_NULL,
    QTYPE_PTR,
    QTYPE_SOA,
    QTYPE_SRV,
    QTYPE_TXT,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    DnsQuestion,
    DnsRecord,
    parse_dns,
    parse_dns_tcp,
    read_name,
)

IN = 1


def header(txid=0x1234, *, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0,
           rcode=0, qd=0, an=0, ns=0, ar=0):
    flags = ((qr & 1) << 15 | (opcode & 0xF) << 11 | (aa & 1) << 10
             | (tc & 1) << 9 | (rd & 1) << 8 | (ra & 1) << 7 | (z & 7) << 4
             | (rcode & 0xF))
    return struct.pack("!HHHHHH", txid, flags, qd, an, ns, ar)


def name(*labels):
    out = b""
    for label in labels:
        raw = label.encode("latin-1") if isinstance(label, str) else label
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def pointer(offset):
    return struct.pack("!H", 0xC000 | offset)


def question(encoded_name, qtype=QTYPE_A, qclass=IN):
    return encoded_name + struct.pack("!HH", qtype, qclass)


def record(encoded_name, rtype=QTYPE_A, rclass=IN, ttl=300,
           rdata=b"\x5d\xb8\xd8\x22", rdlength=None):
    length = len(rdata) if rdlength is None else rdlength
    return (encoded_name + struct.pack("!HHIH", rtype, rclass, ttl, length)
            + rdata)


# --- header ----------------------------------------------------------------

def test_query_header_fields():
    msg = parse_dns(header(0xBEEF, qd=1) + question(name("www", "example", "com")))

    assert msg is not None
    assert msg.txid == 0xBEEF
    assert msg.is_response is False
    assert msg.opcode == 0
    assert msg.rcode == RCODE_NOERROR
    assert msg.truncated_flag is False


def test_response_flags_and_rcode():
    msg = parse_dns(header(1, qr=1, tc=1, rcode=RCODE_NXDOMAIN, qd=1)
                    + question(name("nope", "example", "com")))

    assert msg.is_response is True
    assert msg.truncated_flag is True
    assert msg.rcode == RCODE_NXDOMAIN


@pytest.mark.parametrize("opcode", [0, 1, 2, 4, 5, 6])
def test_assigned_opcodes_accepted(opcode):
    msg = parse_dns(header(1, opcode=opcode, qd=1) + question(name("a", "com")))
    assert msg.opcode == opcode


@pytest.mark.parametrize("opcode", [3, 7, 9, 15])
def test_unassigned_opcode_is_not_dns(opcode):
    assert parse_dns(header(1, opcode=opcode, qd=1)
                     + question(name("a", "com"))) is None


def test_header_only_message_parses():
    msg = parse_dns(header(7, qr=1))

    assert msg.txid == 7
    assert msg.questions == ()
    assert msg.answers == ()


@pytest.mark.parametrize("size", [0, 1, 11])
def test_short_of_a_header_is_rejected(size):
    assert parse_dns(b"\x00" * size) is None


# --- questions -------------------------------------------------------------

def test_question_section_decoded():
    msg = parse_dns(header(qd=1)
                    + question(name("www", "example", "com"), QTYPE_AAAA, IN))

    assert msg.questions == (DnsQuestion("www.example.com", QTYPE_AAAA, IN),)
    assert msg.query_name == "www.example.com"


def test_names_are_lowercased():
    msg = parse_dns(header(qd=1) + question(name("WwW", "ExAmPlE", "COM")))
    assert msg.questions[0].name == "www.example.com"


def test_root_name_is_a_bare_dot():
    msg = parse_dns(header(qd=1) + question(name(), QTYPE_NS))

    assert msg.questions[0].name == "."
    assert msg.questions[0].qtype == QTYPE_NS


def test_multiple_questions():
    payload = (header(qd=3)
               + question(name("a", "test"), QTYPE_A)
               + question(name("b", "test"), QTYPE_TXT)
               + question(name("c", "test"), QTYPE_ANY))
    msg = parse_dns(payload)

    assert [q.name for q in msg.questions] == ["a.test", "b.test", "c.test"]
    assert [q.qtype for q in msg.questions] == [QTYPE_A, QTYPE_TXT, QTYPE_ANY]


def test_label_of_sixty_three_bytes_accepted():
    label = "z" * 63
    msg = parse_dns(header(qd=1) + question(name(label, "com")))
    assert msg.questions[0].name == f"{label}.com"


def test_non_ascii_label_bytes_survive_decoding():
    raw = bytes(range(0x80, 0xBF))
    msg = parse_dns(header(qd=1) + question(name(raw, "tunnel", "example")))

    expected = raw.decode("latin-1").lower()
    assert msg.questions[0].name == f"{expected}.tunnel.example"


def test_control_bytes_in_a_label_do_not_raise():
    raw = bytes([0x00, 0x07, 0x1b, 0xff, 0x2e])
    msg = parse_dns(header(qd=1) + question(name(raw, "exfil", "example")))

    assert msg.questions[0].name.endswith(".exfil.example")


def test_query_name_is_none_without_questions():
    assert parse_dns(header(qr=1)).query_name is None


# --- name length limits ----------------------------------------------------

def test_name_at_the_255_byte_limit_is_accepted():
    labels = ["a" * 63, "b" * 63, "c" * 63, "d" * 61]
    encoded = name(*labels)
    assert len(encoded) == MAX_NAME_LEN

    msg = parse_dns(header(qd=1) + question(encoded))
    assert msg.questions[0].name == ".".join(labels)


def test_name_one_byte_over_the_limit_is_rejected():
    encoded = name("a" * 63, "b" * 63, "c" * 63, "d" * 62)
    assert len(encoded) == MAX_NAME_LEN + 1

    assert parse_dns(header(qd=1) + question(encoded)) is None


def test_oversized_name_is_rejected_before_accumulating():
    encoded = name(*(["q" * 63] * 20))
    assert parse_dns(header(qd=1) + question(encoded)) is None


def test_compression_cannot_be_used_to_exceed_the_limit():
    # A name that is legal on its own, then a second name that appends a
    # pointer back to it enough times to blow past 255 bytes.
    base = name(*(["x" * 63] * 3))
    payload = header(qd=2) + question(base)
    long_name = b"\x3f" + b"y" * 63 + pointer(HEADER_LEN)
    payload += question(long_name)

    msg = parse_dns(payload)
    assert msg is not None
    assert len(msg.questions) == 1


# --- compression -----------------------------------------------------------

def test_answer_name_pointer_resolves_to_the_question_name():
    qname = name("www", "example", "com")
    payload = (header(qr=1, qd=1, an=1)
               + question(qname)
               + record(pointer(HEADER_LEN), QTYPE_A, IN, 60, b"\x01\x02\x03\x04"))
    msg = parse_dns(payload)

    assert msg.answers == (
        DnsRecord("www.example.com", QTYPE_A, IN, 60, b"\x01\x02\x03\x04"),)


def test_partial_compression_prefixes_a_label_onto_a_pointer():
    qname = name("example", "com")
    payload = (header(qr=1, qd=1, an=1)
               + question(qname)
               + record(b"\x04mail" + pointer(HEADER_LEN), QTYPE_A))
    msg = parse_dns(payload)

    assert msg.answers[0].name == "mail.example.com"


def test_pointer_chain_through_two_hops():
    # The first answer's rdata happens to hold a pointer to the question name;
    # the second answer's name points at that, so the chain is two hops deep.
    qname = name("deep", "example", "com")
    hop_at = HEADER_LEN + len(question(qname)) + 2 + 10
    payload = (header(qr=1, qd=1, an=2)
               + question(qname)
               + record(pointer(HEADER_LEN), QTYPE_TXT, IN, 10,
                        pointer(HEADER_LEN))
               + record(pointer(hop_at), QTYPE_CNAME, IN, 10, b"\x00"))
    msg = parse_dns(payload)

    assert [a.name for a in msg.answers] == ["deep.example.com"] * 2


def test_read_name_follows_a_chain_of_pointers():
    buf = name("deep", "example", "com") + pointer(0) + pointer(18)
    assert read_name(buf, 20) == ("deep.example.com", 22)


def test_reading_resumes_after_the_first_pointer_not_after_its_target():
    qname = name("a", "b")
    payload = (header(qr=1, qd=1, an=1)
               + question(qname)
               + record(pointer(HEADER_LEN), QTYPE_MX, IN, 5, b"\xff\xee"))
    msg = parse_dns(payload)

    assert msg.answers[0].rdata == b"\xff\xee"
    assert msg.answers[0].rtype == QTYPE_MX


def test_self_referential_pointer_terminates():
    payload = header(qd=1) + pointer(HEADER_LEN) + struct.pack("!HH", QTYPE_A, IN)

    started = time.monotonic()
    assert parse_dns(payload) is None
    assert time.monotonic() - started < 1.0


def test_two_pointer_loop_terminates():
    # 12 -> 14 -> 12, the classic decompression bomb cycle.
    payload = header(qd=1) + pointer(14) + pointer(HEADER_LEN)

    started = time.monotonic()
    assert parse_dns(payload) is None
    assert time.monotonic() - started < 1.0


def test_long_pointer_cycle_terminates():
    # A ring of 300 pointers, each hopping to the next and the last back to the
    # first: no single hop repeats until the ring closes.
    ring_at = HEADER_LEN
    hops = 300
    ring = b""
    for i in range(hops):
        target = ring_at + 2 * ((i + 1) % hops)
        ring += pointer(target)
    payload = header(qd=1) + ring

    started = time.monotonic()
    assert parse_dns(payload) is None
    assert time.monotonic() - started < 1.0


def test_label_pointing_at_itself_through_a_label_terminates():
    # "a" label followed by a pointer to the start of that same name.
    payload = header(qd=1) + b"\x01a" + pointer(HEADER_LEN)
    assert parse_dns(payload) is None


def test_pointer_past_the_end_of_the_message_is_rejected():
    payload = header(qd=1) + pointer(0x3FFF) + struct.pack("!HH", QTYPE_A, IN)
    assert parse_dns(payload) is None


def test_pointer_into_the_last_byte_is_rejected_when_truncated():
    payload = header(qd=1) + b"\xc0"
    assert parse_dns(payload) is None


def test_forward_pointer_is_followed_when_it_terminates():
    target = HEADER_LEN + 2
    payload = header(qd=1) + pointer(target) + name("fwd", "test")
    payload += struct.pack("!HH", QTYPE_A, IN)

    msg = parse_dns(payload)
    assert msg.questions[0].name == "fwd.test"


# --- reserved and malformed labels -----------------------------------------

@pytest.mark.parametrize("first", [0x40, 0x41, 0x80, 0xBF])
def test_reserved_label_types_are_rejected(first):
    payload = header(qd=1) + bytes([first]) + b"\x00" * 8
    assert parse_dns(payload) is None


def test_label_longer_than_the_remaining_buffer_is_rejected():
    payload = header(qd=1) + b"\x20" + b"short"
    assert parse_dns(payload) is None


def test_name_without_a_terminator_is_rejected():
    payload = header(qd=1) + b"\x03abc\x03def"
    assert parse_dns(payload) is None


def test_question_without_its_type_and_class_is_rejected():
    payload = header(qd=1) + name("a", "com") + b"\x00"
    assert parse_dns(payload) is None


# --- untrusted counts ------------------------------------------------------

def test_absurd_qdcount_stops_at_the_end_of_the_buffer():
    payload = header(qd=0xFFFF) + question(name("only", "one"))

    started = time.monotonic()
    msg = parse_dns(payload)
    assert time.monotonic() - started < 1.0
    assert len(msg.questions) == 1
    assert msg.questions[0].name == "only.one"


def test_absurd_ancount_stops_at_the_end_of_the_buffer():
    payload = (header(qr=1, qd=1, an=0xFFFF)
               + question(name("a", "b"))
               + record(name("a", "b")))
    msg = parse_dns(payload)

    assert len(msg.answers) == 1


def test_qdcount_promising_a_question_that_is_not_there_is_not_dns():
    assert parse_dns(header(qd=1)) is None


def test_answers_are_skipped_when_the_question_section_is_short():
    payload = header(qr=1, qd=2, an=1) + question(name("a", "b"))
    msg = parse_dns(payload)

    assert len(msg.questions) == 1
    assert msg.answers == ()


def test_answer_count_of_zero_ignores_trailing_bytes():
    payload = (header(qr=1, qd=1, an=0)
               + question(name("a", "b"))
               + record(name("a", "b")))
    assert parse_dns(payload).answers == ()


# --- answer records --------------------------------------------------------

def test_answer_record_fields():
    payload = (header(qr=1, qd=1, an=1)
               + question(name("example", "com"))
               + record(name("example", "com"), QTYPE_A, IN, 0x00015180,
                        b"\x5d\xb8\xd8\x22"))
    msg = parse_dns(payload)

    assert msg.answers == (DnsRecord("example.com", QTYPE_A, IN, 86400,
                                     b"\x5d\xb8\xd8\x22"),)


def test_rdata_is_returned_uninterpreted():
    txt = b"\x0bhello world" + b"\xc0\x0c\xff\x00"
    payload = (header(qr=1, qd=1, an=1)
               + question(name("t", "example"), QTYPE_TXT)
               + record(name("t", "example"), QTYPE_TXT, IN, 1, txt))
    msg = parse_dns(payload)

    assert msg.answers[0].rdata == txt


def test_empty_rdata_is_allowed():
    payload = (header(qr=1, qd=1, an=1)
               + question(name("n", "example"), QTYPE_NULL)
               + record(name("n", "example"), QTYPE_NULL, IN, 0, b""))
    assert parse_dns(payload).answers[0].rdata == b""


def test_rdlength_beyond_the_buffer_drops_the_record():
    payload = (header(qr=1, qd=1, an=1)
               + question(name("a", "b"))
               + record(name("a", "b"), rdata=b"\x01\x02", rdlength=4000))
    msg = parse_dns(payload)

    assert msg.answers == ()
    assert msg.questions[0].name == "a.b"


def test_record_truncated_in_its_fixed_fields_drops_it():
    payload = (header(qr=1, qd=1, an=1)
               + question(name("a", "b"))
               + name("a", "b") + b"\x00\x01\x00")
    assert parse_dns(payload).answers == ()


def test_second_answer_survives_when_the_third_is_truncated():
    qname = name("s", "example")
    payload = (header(qr=1, qd=1, an=3)
               + question(qname)
               + record(pointer(HEADER_LEN), QTYPE_A, IN, 30, b"\x01\x01\x01\x01")
               + record(pointer(HEADER_LEN), QTYPE_A, IN, 30, b"\x02\x02\x02\x02")
               + pointer(HEADER_LEN) + b"\x00")
    msg = parse_dns(payload)

    assert [a.rdata for a in msg.answers] == [b"\x01\x01\x01\x01", b"\x02\x02\x02\x02"]


def test_soa_and_srv_records_keep_their_raw_rdata():
    soa_rdata = (name("ns", "example", "com") + name("root", "example", "com")
                 + struct.pack("!IIIII", 1, 2, 3, 4, 5))
    srv_rdata = struct.pack("!HHH", 10, 20, 443) + name("host", "example", "com")
    payload = (header(qr=1, qd=1, an=2)
               + question(name("example", "com"), QTYPE_SOA)
               + record(name("example", "com"), QTYPE_SOA, IN, 60, soa_rdata)
               + record(name("_s", "_tcp", "example", "com"), QTYPE_SRV, IN,
                        60, srv_rdata))
    msg = parse_dns(payload)

    assert msg.answers[0].rdata == soa_rdata
    assert msg.answers[1].rdata == srv_rdata
    assert msg.answers[1].name == "_s._tcp.example.com"


# --- TCP transport ---------------------------------------------------------

def test_tcp_message_behind_its_length_prefix():
    body = header(0x0102, qd=1) + question(name("tcp", "example", "com"))
    msg = parse_dns_tcp(struct.pack("!H", len(body)) + body)

    assert msg.txid == 0x0102
    assert msg.questions[0].name == "tcp.example.com"


def test_tcp_prefix_bounds_the_first_of_two_pipelined_messages():
    first = header(1, qd=1) + question(name("first", "example"))
    second = header(2, qd=1) + question(name("second", "example"))
    payload = (struct.pack("!H", len(first)) + first
               + struct.pack("!H", len(second)) + second)
    msg = parse_dns_tcp(payload)

    assert msg.txid == 1
    assert [q.name for q in msg.questions] == ["first.example"]


def test_tcp_message_split_across_segments_parses_what_arrived():
    body = header(3, qd=1) + question(name("split", "example"))
    payload = struct.pack("!H", len(body) + 500) + body
    msg = parse_dns_tcp(payload)

    assert msg.questions[0].name == "split.example"


@pytest.mark.parametrize("declared", [0, 1, 11])
def test_tcp_length_prefix_below_a_header_is_rejected(declared):
    body = header(qd=0)
    assert parse_dns_tcp(struct.pack("!H", declared) + body) is None


@pytest.mark.parametrize("size", [0, 1, 2, 13])
def test_tcp_payload_too_small_to_hold_a_message(size):
    assert parse_dns_tcp(b"\x00" * size) is None


# --- hostile and arbitrary input -------------------------------------------

def test_every_truncation_of_a_real_message_is_survivable():
    body = (header(0x4242, qr=1, qd=1, an=2)
            + question(name("hunt", "example", "com"))
            + record(pointer(HEADER_LEN), QTYPE_A, IN, 60, b"\x08\x08\x08\x08")
            + record(pointer(HEADER_LEN), QTYPE_CNAME, IN, 60,
                     name("alias", "example", "com")))

    for cut in range(len(body) + 1):
        parse_dns(body[:cut])
        parse_dns_tcp(struct.pack("!H", len(body)) + body[:cut])


def test_every_single_byte_corruption_is_survivable():
    body = (header(1, qr=1, qd=1, an=1)
            + question(name("corrupt", "example", "com"))
            + record(pointer(HEADER_LEN), QTYPE_PTR, IN, 60, b"\x00\x01"))

    for i in range(len(body)):
        for flip in (0x01, 0x40, 0x80, 0xFF):
            mutated = bytearray(body)
            mutated[i] ^= flip
            parse_dns(bytes(mutated))


def test_random_payloads_never_raise():
    rng = random.Random(20240902)
    for _ in range(3000):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96)))
        parse_dns(payload)
        parse_dns_tcp(payload)


def test_pointer_soup_never_raises_and_stays_bounded():
    rng = random.Random(7)
    started = time.monotonic()
    for _ in range(500):
        soup = bytes(rng.choice((0xC0, 0xC1, 0x3F, 0x00, 0xFF))
                     for _ in range(rng.randrange(12, 64)))
        parse_dns(header(qd=4, an=4) + soup)
    assert time.monotonic() - started < 5.0


def test_plain_http_traffic_is_not_mistaken_for_dns():
    assert parse_dns(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n") is None


# --- direct name decoding --------------------------------------------------

def test_read_name_returns_the_offset_after_the_name():
    buf = name("a", "bc") + b"tail"
    assert read_name(buf, 0) == ("a.bc", 6)


def test_read_name_returns_the_offset_after_a_pointer():
    buf = name("a", "bc") + pointer(0)
    assert read_name(buf, 6) == ("a.bc", 8)


def test_read_name_on_the_root_label():
    assert read_name(b"\x00", 0) == (".", 1)


def test_read_name_offset_out_of_range():
    assert read_name(b"\x00", 5) is None


# --- exported constants ----------------------------------------------------

def test_qtype_and_rcode_constants():
    assert (QTYPE_A, QTYPE_NS, QTYPE_CNAME, QTYPE_SOA, QTYPE_NULL) == (1, 2, 5, 6, 10)
    assert (QTYPE_PTR, QTYPE_MX, QTYPE_TXT, QTYPE_AAAA) == (12, 15, 16, 28)
    assert (QTYPE_SRV, QTYPE_ANY) == (33, 255)
    assert (RCODE_NOERROR, RCODE_NXDOMAIN) == (0, 3)
    assert (HEADER_LEN, MAX_NAME_LEN) == (12, 255)


# --- compression chain cost ------------------------------------------------

def chain_of_pointers():
    """A payload that is one long acyclic pointer chain, ending on a root label.

    Every even offset from 12 up holds a pointer to the next one, and the last
    hop lands on a zero byte, so the chain is legal, never repeats a hop and
    stays inside the 14 bit pointer field. qdcount then promises more questions
    than the buffer can hold, so the section walk starts a fresh name every six
    bytes and each one re-walks the rest of the chain.
    """
    total = 0x4000
    body = bytearray(total - HEADER_LEN)
    last = total - 4
    for offset in range(HEADER_LEN, last, 2):
        body[offset - HEADER_LEN:offset - HEADER_LEN + 2] = pointer(offset + 2)
    body[last - HEADER_LEN:last - HEADER_LEN + 2] = pointer(total - 1)
    return header(txid=0, qd=0xFFFF) + bytes(body)


def chained_query(hops):
    """A question whose name is reached through exactly `hops` pointers."""
    chain = b"".join(pointer(HEADER_LEN + 2 * (i + 1)) for i in range(hops))
    return (header(qd=1) + chain + name("end", "example")
            + struct.pack("!HH", QTYPE_A, IN))


def test_acyclic_pointer_chain_is_bounded_not_merely_terminating():
    payload = chain_of_pointers()

    started = time.monotonic()
    parse_dns(payload)
    assert time.monotonic() - started < 0.5


def test_pointer_chain_at_the_cap_still_resolves():
    msg = parse_dns(chained_query(MAX_POINTERS))
    assert msg.questions[0].name == "end.example"


def test_pointer_chain_one_hop_past_the_cap_is_rejected():
    assert parse_dns(chained_query(MAX_POINTERS + 1)) is None


def test_a_realistically_deep_chain_still_resolves():
    msg = parse_dns(chained_query(2))
    assert msg.questions[0].name == "end.example"
