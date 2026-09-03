"""Link and inet decoder tests.

Every packet here is assembled byte by byte from the field layouts in RFC 791,
RFC 8200, RFC 793 and RFC 768, so a passing test means the decoder agrees with
the specification rather than with itself. Malformed and hostile frames are
asserted on explicitly: the contract is None, never an exception.
"""

from __future__ import annotations

import random
import struct

import pytest

from pcapinator.layers import decode, decode_ip, strip_link
from pcapinator.layers.types import (
    ETH_P_IPV4,
    ETH_P_IPV6,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
)
from pcapinator.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    Packet,
)

V4_SRC = bytes((192, 0, 2, 1))
V4_DST = bytes((198, 51, 100, 7))
V4_SRC_TEXT = "192.0.2.1"
V4_DST_TEXT = "198.51.100.7"

V6_SRC = bytes.fromhex("20010db8000000000000000000000001")
V6_DST = bytes.fromhex("20010db8000000000000000000000002")
V6_SRC_TEXT = "2001:db8::1"
V6_DST_TEXT = "2001:db8::2"


# --- frame builders --------------------------------------------------------

def eth(payload: bytes, ethertype: int = ETH_P_IPV4, tags: tuple = ()) -> bytes:
    """Ethernet II: 6 byte destination, 6 byte source, 2 byte type, then tags."""
    head = b"\xaa" * 6 + b"\xbb" * 6
    body = b""
    tpid_chain = [t[0] for t in tags]
    outer = tpid_chain[0] if tags else ethertype
    for index, (_tpid, tci) in enumerate(tags):
        following = tpid_chain[index + 1] if index + 1 < len(tags) else ethertype
        body += struct.pack("!HH", tci, following)
    return head + struct.pack("!H", outer) + body + payload


def ipv4(payload: bytes, proto: int = IPPROTO_TCP, *, ihl: int = 5, ttl: int = 64,
         flags: int = 0, frag_offset: int = 0, total_len: int | None = None,
         version: int = 4, src: bytes = V4_SRC, dst: bytes = V4_DST) -> bytes:
    """RFC 791 header: version/IHL, TOS, total length, id, flags/offset, TTL,
    protocol, checksum, addresses, then IHL-5 words of options."""
    options = b"\x00" * ((ihl - 5) * 4) if ihl > 5 else b""
    hdr_len = 20 + len(options)
    if total_len is None:
        total_len = hdr_len + len(payload)
    frag_field = (flags << 13) | frag_offset
    header = struct.pack(
        "!BBHHHBBH",
        (version << 4) | ihl,
        0,
        total_len,
        0x1234,
        frag_field,
        ttl,
        proto,
        0,
    ) + src + dst + options
    return header + payload


def ipv6(payload: bytes, next_header: int = IPPROTO_TCP, *, hop_limit: int = 63,
         payload_len: int | None = None, version: int = 6,
         src: bytes = V6_SRC, dst: bytes = V6_DST) -> bytes:
    """RFC 8200 header: version/traffic class/flow label, payload length,
    next header, hop limit, then the two 16 byte addresses."""
    if payload_len is None:
        payload_len = len(payload)
    first_word = (version << 28) | (0 << 20) | 0
    return (struct.pack("!IHBB", first_word, payload_len, next_header, hop_limit)
            + src + dst + payload)


def ext_header(next_header: int, hdr_ext_len: int, body_len: int) -> bytes:
    """Hop-by-hop/routing/destination options: next header, length in 8 byte
    units not counting the first 8, then the option data."""
    return struct.pack("!BB", next_header, hdr_ext_len) + b"\x00" * body_len


def ah(next_header: int, payload_len_field: int, body_len: int) -> bytes:
    """RFC 4302 AH: length in 4 byte units, minus 2."""
    return (struct.pack("!BBH", next_header, payload_len_field, 0)
            + b"\x00" * body_len)


def frag_header(next_header: int, offset: int, more: int = 0, ident: int = 1) -> bytes:
    """RFC 8200 fragment header: offset in the top 13 bits, M in the low bit."""
    return struct.pack("!BBHI", next_header, 0, (offset << 3) | more, ident)


def tcp(payload: bytes = b"", *, sport: int = 49152, dport: int = 443,
        flags: int = TCP_SYN, data_offset: int = 5, window: int = 8192) -> bytes:
    """RFC 793 header: ports, sequence, ack, data offset/reserved, flags,
    window, checksum, urgent pointer, then data-offset-5 words of options."""
    options = b"\x00" * ((data_offset - 5) * 4) if data_offset > 5 else b""
    header = struct.pack(
        "!HHIIBBHHH",
        sport, dport,
        0x11111111,
        0x22222222,
        data_offset << 4,
        flags,
        window,
        0,
        0,
    ) + options
    return header + payload


def udp(payload: bytes = b"", *, sport: int = 53, dport: int = 5353,
        length: int | None = None) -> bytes:
    """RFC 768 header: ports, length covering header plus data, checksum."""
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


# --- link layer ------------------------------------------------------------

def test_ethernet_ipv4():
    body = ipv4(tcp())
    assert strip_link(LINKTYPE_ETHERNET, eth(body)) == (ETH_P_IPV4, body, None)


def test_ethernet_ipv6():
    body = ipv6(tcp())
    frame = eth(body, ethertype=ETH_P_IPV6)
    assert strip_link(LINKTYPE_ETHERNET, frame) == (ETH_P_IPV6, body, None)


@pytest.mark.parametrize("ethertype", [0x0806, 0x88CC, 0x0026, 0x0000])
def test_ethernet_non_ip_rejected(ethertype):
    assert strip_link(LINKTYPE_ETHERNET, eth(b"\x00" * 40, ethertype)) is None


@pytest.mark.parametrize("size", [0, 1, 13, 14])
def test_ethernet_too_short(size):
    """14 bytes is a header with nothing above it, which is not an IP frame."""
    assert strip_link(LINKTYPE_ETHERNET, b"\xaa" * size) is None


def test_ethernet_single_vlan():
    body = ipv4(tcp())
    frame = eth(body, tags=((0x8100, 100),))
    assert strip_link(LINKTYPE_ETHERNET, frame) == (ETH_P_IPV4, body, 100)


def test_vlan_id_masks_priority_and_dei_bits():
    """TCI is 3 bits PCP, 1 bit DEI, 12 bits VID."""
    tci = (5 << 13) | (1 << 12) | 100
    frame = eth(ipv4(tcp()), tags=((0x8100, tci),))
    assert strip_link(LINKTYPE_ETHERNET, frame)[2] == 100


def test_qinq_returns_outermost_vlan():
    body = ipv4(tcp())
    frame = eth(body, tags=((0x88A8, 300), (0x8100, 42)))
    assert strip_link(LINKTYPE_ETHERNET, frame) == (ETH_P_IPV4, body, 300)


def test_legacy_9100_tpid():
    frame = eth(ipv4(tcp()), tags=((0x9100, 7),))
    assert strip_link(LINKTYPE_ETHERNET, frame)[2] == 7


def test_four_stacked_tags_accepted():
    body = ipv4(tcp())
    tags = ((0x88A8, 1), (0x8100, 2), (0x8100, 3), (0x8100, 4))
    assert strip_link(LINKTYPE_ETHERNET, eth(body, tags=tags)) == (ETH_P_IPV4, body, 1)


def test_five_stacked_tags_rejected():
    tags = tuple((0x8100, n) for n in range(5))
    assert strip_link(LINKTYPE_ETHERNET, eth(ipv4(tcp()), tags=tags)) is None


def test_endless_vlan_stack_terminates():
    """A frame that is nothing but tags must be refused, not walked."""
    frame = b"\xaa" * 12 + struct.pack("!H", 0x8100) + b"\x81\x00\x00\x00" * 500
    assert strip_link(LINKTYPE_ETHERNET, frame) is None


def test_vlan_tag_cut_short():
    frame = b"\xaa" * 12 + struct.pack("!H", 0x8100) + b"\x00\x64"
    assert strip_link(LINKTYPE_ETHERNET, frame) is None


def test_vlan_with_no_payload():
    frame = b"\xaa" * 12 + struct.pack("!H", 0x8100) + struct.pack("!HH", 1, ETH_P_IPV4)
    assert strip_link(LINKTYPE_ETHERNET, frame) is None


def test_linux_sll():
    """SLL: packet type, ARPHRD type, address length, 8 address bytes, protocol."""
    body = ipv4(tcp())
    header = struct.pack("!HHH", 0, 1, 6) + b"\xaa" * 8 + struct.pack("!H", ETH_P_IPV4)
    assert len(header) == 16
    assert strip_link(LINKTYPE_LINUX_SLL, header + body) == (ETH_P_IPV4, body, None)


def test_linux_sll_non_ip():
    header = struct.pack("!HHH", 0, 1, 6) + b"\xaa" * 8 + struct.pack("!H", 0x0806)
    assert strip_link(LINKTYPE_LINUX_SLL, header + b"\x00" * 20) is None


@pytest.mark.parametrize("size", [0, 15, 16])
def test_linux_sll_too_short(size):
    assert strip_link(LINKTYPE_LINUX_SLL, b"\x00" * size) is None


def test_linux_sll2():
    """SLL2: protocol, reserved, interface index, ARPHRD type, packet type,
    address length, 8 address bytes."""
    body = ipv6(tcp())
    header = (struct.pack("!HHIHBB", ETH_P_IPV6, 0, 3, 1, 0, 6) + b"\xaa" * 8)
    assert len(header) == 20
    assert strip_link(LINKTYPE_LINUX_SLL2, header + body) == (ETH_P_IPV6, body, None)


@pytest.mark.parametrize("size", [0, 19, 20])
def test_linux_sll2_too_short(size):
    header = struct.pack("!HHIHBB", ETH_P_IPV4, 0, 3, 1, 0, 6) + b"\xaa" * 8
    assert strip_link(LINKTYPE_LINUX_SLL2, header[:size]) is None


def test_linux_sll2_non_ip():
    header = struct.pack("!HHIHBB", 0x0806, 0, 3, 1, 0, 6) + b"\xaa" * 8
    assert strip_link(LINKTYPE_LINUX_SLL2, header + b"\x00" * 28) is None


@pytest.mark.parametrize("endian", ["<", ">"])
def test_null_af_inet_either_byte_order(endian):
    body = ipv4(tcp())
    frame = struct.pack(endian + "I", 2) + body
    assert strip_link(LINKTYPE_NULL, frame) == (ETH_P_IPV4, body, None)


@pytest.mark.parametrize("family", [24, 28, 30])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_null_af_inet6_variants(family, endian):
    body = ipv6(tcp())
    frame = struct.pack(endian + "I", family) + body
    assert strip_link(LINKTYPE_NULL, frame) == (ETH_P_IPV6, body, None)


@pytest.mark.parametrize("family", [0, 1, 7, 17, 0xFFFFFFFF])
def test_null_unknown_family(family):
    frame = struct.pack("<I", family) + ipv4(tcp())
    assert strip_link(LINKTYPE_NULL, frame) is None


@pytest.mark.parametrize("size", [0, 3, 4])
def test_null_too_short(size):
    """4 bytes is a family with no packet above it."""
    assert strip_link(LINKTYPE_NULL, struct.pack("<I", 2)[:size]) is None


def test_raw_infers_version():
    v4, v6 = ipv4(tcp()), ipv6(tcp())
    assert strip_link(LINKTYPE_RAW, v4) == (ETH_P_IPV4, v4, None)
    assert strip_link(LINKTYPE_RAW, v6) == (ETH_P_IPV6, v6, None)


@pytest.mark.parametrize("first", [0x00, 0x50, 0x70, 0xF0])
def test_raw_bad_version_nibble(first):
    assert strip_link(LINKTYPE_RAW, bytes([first]) + b"\x00" * 40) is None


def test_raw_empty():
    assert strip_link(LINKTYPE_RAW, b"") is None


def test_bare_ip_linktypes():
    v4, v6 = ipv4(tcp()), ipv6(tcp())
    assert strip_link(LINKTYPE_IPV4, v4) == (ETH_P_IPV4, v4, None)
    assert strip_link(LINKTYPE_IPV6, v6) == (ETH_P_IPV6, v6, None)
    assert strip_link(LINKTYPE_IPV4, b"") is None


@pytest.mark.parametrize("linktype", [3, 105, 127, 195, 276000, -1])
def test_unsupported_linktype(linktype):
    assert strip_link(linktype, b"\x00" * 64) is None


# --- IPv4 ------------------------------------------------------------------

def call(data: bytes, ethertype: int = ETH_P_IPV4, *, wirelen: int = 0,
         vlan=None, truncated: bool = False):
    return decode_ip(1.5, ethertype, data, wirelen or len(data), vlan, truncated)


def test_ipv4_tcp_fields():
    frame = call(ipv4(tcp(b"hello", sport=1234, dport=80, flags=TCP_SYN | TCP_ACK)))
    assert frame.src == V4_SRC_TEXT and frame.dst == V4_DST_TEXT
    assert frame.proto == IPPROTO_TCP
    assert (frame.sport, frame.dport) == (1234, 80)
    assert frame.payload == b"hello"
    assert frame.ttl == 64
    assert frame.ip_version == 4
    assert frame.is_synack and not frame.is_syn
    assert not frame.fragmented and not frame.truncated


def test_ipv4_options_honoured():
    """IHL 8 means 12 bytes of options that are not payload."""
    frame = call(ipv4(tcp(b"body"), ihl=8))
    assert frame.payload == b"body"
    assert (frame.sport, frame.dport) == (49152, 443)


@pytest.mark.parametrize("ihl", [0, 1, 4])
def test_ipv4_ihl_below_five_rejected(ihl):
    assert call(ipv4(tcp(), ihl=ihl)) is None


def test_ipv4_ihl_beyond_captured_bytes():
    """IHL 15 claims a 60 byte header while only 20 bytes were captured."""
    header = bytearray(ipv4(b""))
    header[0] = (4 << 4) | 15
    assert call(bytes(header)) is None


@pytest.mark.parametrize("size", [0, 1, 19])
def test_ipv4_too_short(size):
    assert call(ipv4(tcp())[:size]) is None


def test_ipv4_version_mismatch_rejected():
    assert call(ipv4(tcp(), version=6)) is None


def test_ipv4_total_length_strips_link_padding():
    """A 60 byte minimum ethernet frame pads a short packet; the pad is not
    payload."""
    body = ipv4(udp(b"ab"), proto=IPPROTO_UDP)
    frame = call(body + b"\x00" * 20)
    assert frame.payload == b"ab"


def test_ipv4_total_length_beyond_capture_is_ignored():
    frame = call(ipv4(tcp(b"data"), total_len=60000))
    assert frame.payload == b"data"


def test_ipv4_total_length_below_header_is_ignored():
    frame = call(ipv4(tcp(b"data"), total_len=0))
    assert frame.payload == b"data"


def test_ipv4_udp_payload_bounded_by_length_field():
    frame = call(ipv4(udp(b"0123456789", length=12), proto=IPPROTO_UDP))
    assert frame.payload == b"0123"
    assert (frame.sport, frame.dport) == (53, 5353)


def test_ipv4_udp_length_larger_than_capture():
    """A lying length field must not read past the buffer."""
    frame = call(ipv4(udp(b"abc", length=65535), proto=IPPROTO_UDP))
    assert frame.payload == b"abc"


@pytest.mark.parametrize("length", [0, 1, 7])
def test_ipv4_udp_undersized_length_field(length):
    frame = call(ipv4(udp(b"abc", length=length), proto=IPPROTO_UDP))
    assert frame.payload == b"abc"


@pytest.mark.parametrize("size", [0, 1, 7])
def test_ipv4_udp_header_cut_short(size):
    assert call(ipv4(b"\x00" * size, proto=IPPROTO_UDP)) is None


def test_ipv4_icmp():
    message = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"payload"
    frame = call(ipv4(message, proto=IPPROTO_ICMP))
    assert (frame.sport, frame.dport, frame.flags) == (0, 0, 0)
    assert frame.payload == message


def test_ipv4_unknown_protocol_still_reported():
    """Scan detection needs to see protocol sweeps, so GRE is not dropped."""
    frame = call(ipv4(b"\xde\xad\xbe\xef", proto=47))
    assert frame.proto == 47
    assert (frame.sport, frame.dport) == (0, 0)
    assert frame.payload == b"\xde\xad\xbe\xef"


def test_ipv4_later_fragment_has_no_transport_header():
    """Offset 185 means these bytes are user data, not a TCP header."""
    body = ipv4(b"A" * 40, proto=IPPROTO_TCP, flags=0x1, frag_offset=185)
    frame = call(body)
    assert frame.fragmented
    assert (frame.sport, frame.dport, frame.flags) == (0, 0, 0)
    assert frame.payload == b""
    assert frame.proto == IPPROTO_TCP


def test_ipv4_first_fragment_is_parsed():
    frame = call(ipv4(tcp(b"start", dport=8080), flags=0x1, frag_offset=0))
    assert frame.fragmented
    assert frame.dport == 8080
    assert frame.payload == b"start"


def test_ipv4_dont_fragment_is_not_fragmentation():
    frame = call(ipv4(tcp(), flags=0x2))
    assert not frame.fragmented


def test_tcp_flags_are_the_whole_wire_byte():
    """Byte 13 of the header is eight flag bits: CWR, ECE, URG, ACK, PSH, RST,
    SYN, FIN. Discarding CWR/ECE cannot be undone downstream, and it makes an
    ECN-marked packet read as flags == 0, which is a null scan."""
    assert call(ipv4(tcp(flags=0x40))).flags == 0x40   # ECE alone
    assert call(ipv4(tcp(flags=0x80))).flags == 0x80   # CWR alone
    assert call(ipv4(tcp(flags=0))).flags == 0         # a real null scan

    ecn_syn = call(ipv4(tcp(flags=0xC0 | TCP_SYN)))
    assert ecn_syn.flags == 0xC2 and ecn_syn.is_syn

    every_bit = call(ipv4(tcp(flags=0xFF)))
    named = TCP_FIN | TCP_SYN | TCP_RST | TCP_PSH | TCP_ACK | TCP_URG
    assert every_bit.flags == 0xFF and every_bit.flags & named == named


@pytest.mark.parametrize("data_offset", [0, 1, 4])
def test_tcp_data_offset_below_five_rejected(data_offset):
    assert call(ipv4(tcp(b"x" * 40, data_offset=data_offset))) is None


def test_tcp_data_offset_beyond_capture_keeps_ports():
    """A snaplen cut the options off; ports and flags survive, payload does not."""
    body = ipv4(tcp(data_offset=15))[:40]
    frame = call(body)
    assert (frame.sport, frame.dport) == (49152, 443)
    assert frame.payload == b""


@pytest.mark.parametrize("size", [0, 1, 19])
def test_tcp_header_cut_short(size):
    assert call(ipv4(b"\x00" * size)) is None


def test_ipv4_ttl_extracted():
    assert call(ipv4(tcp(), ttl=1)).ttl == 1
    assert call(ipv4(tcp(), ttl=255)).ttl == 255


def test_metadata_passed_through():
    frame = call(ipv4(tcp()), wirelen=1514, vlan=42, truncated=True)
    assert frame.wirelen == 1514 and frame.vlan == 42 and frame.truncated
    assert frame.ts == 1.5


# --- IPv6 ------------------------------------------------------------------

def call6(data: bytes, **kw):
    return call(data, ETH_P_IPV6, **kw)


def test_ipv6_tcp_fields():
    frame = call6(ipv6(tcp(b"hi", sport=1, dport=2, flags=TCP_RST)))
    assert frame.src == V6_SRC_TEXT and frame.dst == V6_DST_TEXT
    assert frame.ip_version == 6
    assert frame.ttl == 63
    assert (frame.sport, frame.dport) == (1, 2)
    assert frame.flags == TCP_RST
    assert frame.payload == b"hi"


@pytest.mark.parametrize("size", [0, 1, 39])
def test_ipv6_too_short(size):
    assert call6(ipv6(tcp())[:size]) is None


def test_ipv6_version_mismatch_rejected():
    assert call6(ipv6(tcp(), version=4)) is None


def test_ipv6_payload_length_strips_padding():
    body = udp(b"xy")
    frame = call6(ipv6(body, next_header=IPPROTO_UDP) + b"\x00" * 16)
    assert frame.payload == b"xy"


def test_ipv6_zero_payload_length_is_not_a_trim():
    """Zero means jumbogram, so it must not truncate the packet to nothing."""
    frame = call6(ipv6(tcp(b"body"), payload_len=0))
    assert frame.payload == b"body"


def test_ipv6_hop_by_hop_then_udp():
    chain = ext_header(IPPROTO_UDP, 0, 6) + udp(b"dns")
    frame = call6(ipv6(chain, next_header=0))
    assert frame.proto == IPPROTO_UDP
    assert frame.payload == b"dns"


def test_ipv6_ext_length_units_are_eight_bytes():
    """hdr_ext_len 2 means 8 + 2*8 = 24 bytes."""
    chain = ext_header(IPPROTO_UDP, 2, 22) + udp(b"ok")
    frame = call6(ipv6(chain, next_header=60))
    assert frame.payload == b"ok"


def test_ipv6_full_chain():
    chain = (ext_header(43, 0, 6)
             + ext_header(60, 0, 6)
             + ext_header(IPPROTO_TCP, 1, 14)
             + tcp(b"deep", dport=8443))
    frame = call6(ipv6(chain, next_header=0))
    assert frame.proto == IPPROTO_TCP
    assert frame.dport == 8443
    assert frame.payload == b"deep"


def test_ipv6_ah_uses_four_byte_units():
    """AH payload length 4 means (4 + 2) * 4 = 24 bytes, not 40."""
    chain = ah(IPPROTO_UDP, 4, 20) + udp(b"ah")
    assert len(chain) - len(udp(b"ah")) == 24
    frame = call6(ipv6(chain, next_header=51))
    assert frame.proto == IPPROTO_UDP
    assert frame.payload == b"ah"


def test_ipv6_ah_minimum_length():
    chain = ah(IPPROTO_ICMPV6, 0, 4) + b"\x80\x00\x00\x00"
    frame = call6(ipv6(chain, next_header=51))
    assert frame.proto == IPPROTO_ICMPV6
    assert frame.payload == b"\x80\x00\x00\x00"


def test_ipv6_first_fragment_is_parsed():
    chain = frag_header(IPPROTO_TCP, 0, more=1) + tcp(b"head", dport=993)
    frame = call6(ipv6(chain, next_header=44))
    assert frame.fragmented
    assert frame.dport == 993
    assert frame.payload == b"head"


def test_ipv6_later_fragment_has_no_transport_header():
    chain = frag_header(IPPROTO_TCP, 185) + b"B" * 32
    frame = call6(ipv6(chain, next_header=44))
    assert frame.fragmented
    assert frame.proto == IPPROTO_TCP
    assert (frame.sport, frame.dport) == (0, 0)
    assert frame.payload == b""


def test_ipv6_icmpv6():
    message = struct.pack("!BBH", 128, 0, 0) + b"\x00" * 4 + b"ping"
    frame = call6(ipv6(message, next_header=IPPROTO_ICMPV6))
    assert frame.proto == IPPROTO_ICMPV6
    assert (frame.sport, frame.dport) == (0, 0)
    assert frame.payload == message


def test_ipv6_no_next_header():
    frame = call6(ipv6(b"", next_header=59))
    assert frame.proto == 59 and frame.payload == b""


def test_ipv6_unknown_protocol_still_reported():
    frame = call6(ipv6(b"\x01\x02", next_header=132))
    assert frame.proto == 132 and frame.payload == b"\x01\x02"


def test_ipv6_chain_depth_capped():
    """Eight nested headers decode; a ninth is refused rather than walked."""
    eight = ext_header(60, 0, 6) * 7 + ext_header(IPPROTO_UDP, 0, 6) + udp(b"x")
    assert call6(ipv6(eight, next_header=0)).payload == b"x"
    nine = ext_header(60, 0, 6) * 8 + ext_header(IPPROTO_UDP, 0, 6) + udp(b"x")
    assert call6(ipv6(nine, next_header=0)) is None


def test_ipv6_endless_chain_terminates():
    """Every header points at another of its own kind."""
    body = ext_header(60, 0, 6) * 2000
    assert call6(ipv6(body, next_header=60)) is None


def test_ipv6_ext_length_past_buffer():
    chain = ext_header(IPPROTO_UDP, 200, 6) + udp(b"x")
    assert call6(ipv6(chain, next_header=0)) is None


def test_ipv6_ah_length_past_buffer():
    assert call6(ipv6(ah(IPPROTO_UDP, 255, 4), next_header=51)) is None


@pytest.mark.parametrize("tail", [b"", b"\x11"])
def test_ipv6_ext_header_cut_short(tail):
    assert call6(ipv6(tail, next_header=0)) is None


@pytest.mark.parametrize("size", [0, 2, 7])
def test_ipv6_fragment_header_cut_short(size):
    """A fragment header is 8 bytes; anything less cannot be read."""
    partial = frag_header(IPPROTO_TCP, 0)[:size]
    assert call6(ipv6(partial, next_header=44)) is None


# --- decode() end to end ---------------------------------------------------

def packet(data: bytes, linktype: int = LINKTYPE_ETHERNET, *, wirelen=None,
           ts: float = 10.25) -> Packet:
    return Packet(ts, len(data), wirelen or len(data), linktype, data)


def test_decode_end_to_end():
    raw = eth(ipv4(tcp(b"GET / HTTP/1.1", dport=80, flags=TCP_PSH | TCP_ACK)),
              tags=((0x8100, 12),))
    frame = decode(packet(raw))
    assert frame.src == V4_SRC_TEXT
    assert frame.dport == 80
    assert frame.vlan == 12
    assert frame.payload == b"GET / HTTP/1.1"
    assert frame.wirelen == len(raw)
    assert frame.ts == 10.25
    assert not frame.truncated


def test_decode_marks_truncation_and_wire_length():
    raw = eth(ipv4(tcp(b"partial")))
    frame = decode(packet(raw, wirelen=1514))
    assert frame.truncated and frame.wirelen == 1514


def test_ethertype_and_ip_version_must_agree():
    """A frame that claims IPv4 but carries an IPv6 header is not decoded as
    either."""
    assert decode(packet(eth(ipv6(tcp()), ethertype=ETH_P_IPV4))) is None
    assert decode(packet(eth(ipv4(tcp()), ethertype=ETH_P_IPV6))) is None


def test_decode_non_ip_returns_none():
    assert decode(packet(eth(b"\x00" * 28, 0x0806))) is None
    assert decode(packet(b"", LINKTYPE_ETHERNET)) is None


def test_decode_over_every_linktype():
    body = ipv4(udp(b"z", dport=53), proto=IPPROTO_UDP)
    frames = [
        packet(eth(body)),
        packet(struct.pack("!HHH", 0, 1, 6) + b"\x00" * 8
               + struct.pack("!H", ETH_P_IPV4) + body, LINKTYPE_LINUX_SLL),
        packet(struct.pack("!HHIHBB", ETH_P_IPV4, 0, 1, 1, 0, 6) + b"\x00" * 8
               + body, LINKTYPE_LINUX_SLL2),
        packet(struct.pack("<I", 2) + body, LINKTYPE_NULL),
        packet(body, LINKTYPE_RAW),
        packet(body, LINKTYPE_IPV4),
    ]
    for pkt in frames:
        frame = decode(pkt)
        assert frame is not None and frame.dport == 53 and frame.payload == b"z"


# --- hostile input ---------------------------------------------------------

LINKTYPES = [LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL,
             LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2]


def test_random_bytes_never_raise():
    rng = random.Random(20240901)
    for _ in range(4000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 80)))
        for linktype in LINKTYPES:
            decode(packet(data, linktype))


def test_truncation_at_every_offset_never_raises():
    """Every prefix of a well formed frame is a capture cut short somewhere."""
    full = eth(ipv6(ext_header(44, 0, 6) + frag_header(IPPROTO_TCP, 0)
                    + tcp(b"payload"), next_header=0),
               ethertype=ETH_P_IPV6)
    for cut in range(len(full) + 1):
        decode(packet(full[:cut]))

    full4 = eth(ipv4(tcp(b"payload", data_offset=8), ihl=7))
    for cut in range(len(full4) + 1):
        decode(packet(full4[:cut]))


def test_every_single_byte_corruption_never_raises():
    full = eth(ipv4(tcp(b"data")))
    for index in range(len(full)):
        for value in (0x00, 0x0F, 0xF0, 0xFF):
            mutated = full[:index] + bytes([value]) + full[index + 1:]
            decode(packet(mutated))


def test_lying_length_fields_never_over_read():
    """Maximal length fields on a minimal packet."""
    body = bytearray(ipv4(udp(b"", length=65535), proto=IPPROTO_UDP, total_len=65535))
    frame = call(bytes(body))
    assert frame.payload == b""

    v6 = ipv6(tcp(), payload_len=65535)
    assert call6(v6).payload == b""
