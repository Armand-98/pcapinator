"""Capture reader tests built from hand-assembled bytes.

Every fixture is constructed field by field from the format specifications, so
a passing test means the reader agrees with the spec rather than with itself.
"""

import gzip
import struct

import pytest

from pcapinator.pcap import CaptureError, Packet, read_packets

PCAP_MAGICS = {
    ("<", False): b"\xd4\xc3\xb2\xa1",
    (">", False): b"\xa1\xb2\xc3\xd4",
    ("<", True): b"\x4d\x3c\xb2\xa1",
    (">", True): b"\xa1\xb2\x3c\x4d",
}


def build_pcap(records, *, endian="<", nano=False, linktype=1, snaplen=65535):
    out = PCAP_MAGICS[(endian, nano)]
    out += struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for ts_sec, ts_frac, wirelen, data in records:
        out += struct.pack(endian + "IIII", ts_sec, ts_frac, len(data), wirelen)
        out += data
    return out


def build_block(block_type, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return (struct.pack(endian + "II", block_type, total) + body
            + struct.pack(endian + "I", total))


def build_shb(endian="<"):
    bom = b"\x1a\x2b\x3c\x4d" if endian == ">" else b"\x4d\x3c\x2b\x1a"
    return build_block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1), endian)


def build_idb(*, linktype=1, snaplen=65535, tsresol=None, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
        body += struct.pack(endian + "HH", 0, 0)
    return build_block(1, body, endian)


def build_epb(iface, ticks, data, *, wirelen=None, endian="<"):
    wirelen = len(data) if wirelen is None else wirelen
    body = struct.pack(endian + "IIIII", iface, ticks >> 32,
                       ticks & 0xFFFFFFFF, len(data), wirelen)
    body += data + b"\x00" * (-len(data) % 4)
    return build_block(6, body, endian)


def build_spb(data, *, wirelen=None, endian="<"):
    wirelen = len(data) if wirelen is None else wirelen
    body = struct.pack(endian + "I", wirelen) + data + b"\x00" * (-len(data) % 4)
    return build_block(3, body, endian)


def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


# --- libpcap ---------------------------------------------------------------

@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcap_roundtrip_both_byte_orders(tmp_path, endian):
    raw = build_pcap([
        (1_700_000_000, 500_000, 74, b"\xaa" * 74),
        (1_700_000_001, 250_000, 98, b"\xbb" * 60),
    ], endian=endian)

    packets = list(read_packets(write(tmp_path, "c.pcap", raw)))

    assert len(packets) == 2
    assert packets[0].ts == pytest.approx(1_700_000_000.5)
    assert packets[0].caplen == 74
    assert packets[0].wirelen == 74
    assert packets[0].linktype == 1
    assert packets[0].data == b"\xaa" * 74
    assert not packets[0].truncated

    assert packets[1].ts == pytest.approx(1_700_000_001.25)
    assert packets[1].caplen == 60
    assert packets[1].wirelen == 98
    assert packets[1].truncated, "snaplen-clipped packet must report as truncated"


def test_pcap_nanosecond_magic_scales_the_fraction(tmp_path):
    raw = build_pcap([(1_700_000_000, 500_000_000, 4, b"data")], nano=True)
    (packet,) = list(read_packets(write(tmp_path, "n.pcap", raw)))
    assert packet.ts == pytest.approx(1_700_000_000.5)


def test_pcap_linktype_is_carried_onto_every_packet(tmp_path):
    raw = build_pcap([(1, 0, 4, b"data")], linktype=101)
    (packet,) = list(read_packets(write(tmp_path, "raw.pcap", raw)))
    assert packet.linktype == 101


def test_gzipped_capture_is_read_transparently(tmp_path):
    raw = build_pcap([(1, 0, 4, b"data")])
    path = tmp_path / "c.pcap.gz"
    path.write_bytes(gzip.compress(raw))
    assert len(list(read_packets(path))) == 1


# --- truncation ------------------------------------------------------------

def test_truncation_mid_packet_yields_prefix_then_stops(tmp_path):
    raw = build_pcap([(1, 0, 10, b"\x01" * 10), (2, 0, 10, b"\x02" * 10)])
    path = write(tmp_path, "cut.pcap", raw[:-4])
    packets = list(read_packets(path))
    assert len(packets) == 1
    assert packets[0].data == b"\x01" * 10


def test_truncation_is_an_error_under_strict(tmp_path):
    raw = build_pcap([(1, 0, 10, b"\x01" * 10), (2, 0, 10, b"\x02" * 10)])
    path = write(tmp_path, "cut.pcap", raw[:-4])
    with pytest.raises(CaptureError, match="mid packet"):
        list(read_packets(path, strict=True))


def test_truncated_file_header_is_always_an_error(tmp_path):
    path = write(tmp_path, "stub.pcap", PCAP_MAGICS[("<", False)] + b"\x00" * 8)
    with pytest.raises(CaptureError, match="truncated pcap file header"):
        list(read_packets(path))


# --- hostile input ---------------------------------------------------------

def test_absurd_captured_length_is_refused_without_allocating(tmp_path):
    """A capture claiming a 4 GiB packet must fail, not try to read it."""
    raw = PCAP_MAGICS[("<", False)]
    raw += struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    raw += struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    path = write(tmp_path, "bomb.pcap", raw)
    with pytest.raises(CaptureError, match="refusing to allocate"):
        list(read_packets(path))


def test_absurd_block_length_is_refused(tmp_path):
    raw = build_shb() + struct.pack("<II", 6, 0xFFFFFFFF)
    path = write(tmp_path, "bomb.pcapng", raw)
    with pytest.raises(CaptureError, match="implausible length"):
        list(read_packets(path))


def test_empty_and_unknown_files_are_rejected(tmp_path):
    with pytest.raises(CaptureError, match="empty capture file"):
        list(read_packets(write(tmp_path, "empty.pcap", b"")))
    with pytest.raises(CaptureError, match="unrecognised capture format"):
        list(read_packets(write(tmp_path, "junk.pcap", b"not a capture at all")))


# --- pcapng ----------------------------------------------------------------

@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_roundtrip_both_byte_orders(tmp_path, endian):
    raw = (build_shb(endian)
           + build_idb(linktype=1, endian=endian)
           + build_epb(0, 1_700_000_000_500_000, b"\xaa" * 20, endian=endian)
           + build_epb(0, 1_700_000_001_000_000, b"\xbb" * 21, wirelen=99, endian=endian))

    packets = list(read_packets(write(tmp_path, "c.pcapng", raw)))

    assert len(packets) == 2
    assert packets[0].ts == pytest.approx(1_700_000_000.5)
    assert packets[0].data == b"\xaa" * 20
    assert packets[0].linktype == 1
    # A 21 byte payload is padded to 24 in the block; caplen must survive it.
    assert packets[1].caplen == 21
    assert packets[1].data == b"\xbb" * 21
    assert packets[1].wirelen == 99


def test_pcapng_timestamp_resolution_option_is_honoured(tmp_path):
    raw = (build_shb() + build_idb(tsresol=9)
           + build_epb(0, 1_700_000_000_500_000_000, b"x" * 4))
    (packet,) = list(read_packets(write(tmp_path, "ns.pcapng", raw)))
    assert packet.ts == pytest.approx(1_700_000_000.5)


def test_pcapng_power_of_two_timestamp_resolution(tmp_path):
    raw = (build_shb() + build_idb(tsresol=0x80 | 10)
           + build_epb(0, 512, b"x" * 4))
    (packet,) = list(read_packets(write(tmp_path, "p2.pcapng", raw)))
    assert packet.ts == pytest.approx(0.5)


def test_pcapng_packets_resolve_their_own_interface_linktype(tmp_path):
    raw = (build_shb()
           + build_idb(linktype=1)
           + build_idb(linktype=113)
           + build_epb(0, 1_000_000, b"eth0")
           + build_epb(1, 2_000_000, b"sll0"))
    packets = list(read_packets(write(tmp_path, "multi.pcapng", raw)))
    assert [p.linktype for p in packets] == [1, 113]


def test_pcapng_new_section_resets_the_interface_table(tmp_path):
    raw = (build_shb() + build_idb(linktype=1) + build_epb(0, 1_000_000, b"aaaa")
           + build_shb() + build_idb(linktype=101) + build_epb(0, 2_000_000, b"bbbb"))
    packets = list(read_packets(write(tmp_path, "sections.pcapng", raw)))
    assert [p.linktype for p in packets] == [1, 101]


def test_pcapng_packet_on_undeclared_interface_is_skipped(tmp_path):
    raw = build_shb() + build_idb() + build_epb(7, 1_000_000, b"ghost")
    path = write(tmp_path, "ghost.pcapng", raw)
    assert list(read_packets(path)) == []
    with pytest.raises(CaptureError, match="undeclared interface"):
        list(read_packets(path, strict=True))


def test_pcapng_simple_packet_block(tmp_path):
    raw = build_shb() + build_idb(linktype=1) + build_spb(b"\xcc" * 16, wirelen=40)
    (packet,) = list(read_packets(write(tmp_path, "spb.pcapng", raw)))
    assert packet.wirelen == 40
    assert packet.caplen == 16
    assert packet.data == b"\xcc" * 16


def test_pcapng_unknown_blocks_are_skipped(tmp_path):
    raw = (build_shb() + build_idb()
           + build_block(0x00000005, b"\x00" * 32)   # interface statistics
           + build_epb(0, 1_000_000, b"kept"))
    (packet,) = list(read_packets(write(tmp_path, "skip.pcapng", raw)))
    assert packet.data == b"kept"


def test_pcapng_without_section_header_is_rejected(tmp_path):
    """A pcapng body with no leading section header carries no byte-order magic,
    so it is unidentifiable rather than merely malformed."""
    raw = build_idb() + build_epb(0, 1_000_000, b"orphan")
    with pytest.raises(CaptureError, match="unrecognised capture format"):
        list(read_packets(write(tmp_path, "nosec.pcapng", raw)))


def test_packet_is_immutable(tmp_path):
    raw = build_pcap([(1, 0, 4, b"data")])
    (packet,) = list(read_packets(write(tmp_path, "c.pcap", raw)))
    with pytest.raises(AttributeError):
        packet.ts = 0  # type: ignore[misc]
