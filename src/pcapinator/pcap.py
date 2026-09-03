"""Readers for the libpcap and pcapng capture file formats.

Both layouts are decoded directly from their on-disk bytes rather than through a
capture library, so the standard library is the only requirement.

Capture files are treated as untrusted input. A threat hunting tool ingests data
an attacker influenced by definition, so every length field is bounded before it
is used to allocate, and a hostile file raises CaptureError instead of
exhausting memory.
"""

from __future__ import annotations

import gzip
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


class CaptureError(Exception):
    """A capture file is malformed beyond recovery."""


# Larger than any real frame, including jumbo and USB captures, but small enough
# that a bogus length field cannot exhaust memory.
MAX_PACKET_BYTES = 1 << 26
MAX_BLOCK_BYTES = 1 << 26

PCAP_MAGIC_US_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_US_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
GZIP_MAGIC = b"\x1f\x8b"

_PCAP_MAGICS = {
    PCAP_MAGIC_US_BE: (">", 1_000_000),
    PCAP_MAGIC_US_LE: ("<", 1_000_000),
    PCAP_MAGIC_NS_BE: (">", 1_000_000_000),
    PCAP_MAGIC_NS_LE: ("<", 1_000_000_000),
}

# Link types decoded downstream; see tcpdump.org/linktypes.html.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276


@dataclass(frozen=True, slots=True)
class Packet:
    ts: float
    caplen: int
    wirelen: int
    linktype: int
    data: bytes

    @property
    def truncated(self) -> bool:
        """True when the capture stored less than the frame carried on the wire."""
        return self.caplen < self.wirelen


def read_packets(path: str | Path, *, strict: bool = False) -> Iterator[Packet]:
    """Yield packets from a libpcap or pcapng file, optionally gzipped.

    Captures cut short by a killed capture process are common in the field, so
    iteration stops cleanly at a truncation by default. strict=True raises
    CaptureError instead, which is what the test suite asserts against.
    """
    with _open(Path(path)) as fh:
        magic = fh.read(4)
        if not magic:
            raise CaptureError("empty capture file")
        fh.seek(0)
        if magic == PCAPNG_MAGIC:
            yield from _iter_pcapng(fh, strict)
        elif magic in _PCAP_MAGICS:
            yield from _iter_pcap(fh, strict)
        else:
            raise CaptureError(f"unrecognised capture format (magic {magic.hex()})")


def _open(path: Path) -> BinaryIO:
    with open(path, "rb") as probe:
        compressed = probe.read(2) == GZIP_MAGIC
    return gzip.open(path, "rb") if compressed else open(path, "rb")


# --- libpcap ---------------------------------------------------------------

def _iter_pcap(fh: BinaryIO, strict: bool) -> Iterator[Packet]:
    head = fh.read(24)
    if len(head) < 24:
        raise CaptureError("truncated pcap file header")

    magic = head[:4]
    if magic not in _PCAP_MAGICS:
        raise CaptureError(f"not a pcap file (magic {magic.hex()})")
    endian, ts_units = _PCAP_MAGICS[magic]

    linktype = struct.unpack(endian + "HHiIII", head[4:])[5]

    while True:
        record = fh.read(16)
        if not record:
            return
        if len(record) < 16:
            if strict:
                raise CaptureError("capture ends mid record header")
            return

        ts_sec, ts_frac, caplen, wirelen = struct.unpack(endian + "IIII", record)
        if caplen > MAX_PACKET_BYTES:
            raise CaptureError(f"record claims {caplen} bytes, refusing to allocate")

        data = fh.read(caplen)
        if len(data) < caplen:
            if strict:
                raise CaptureError("capture ends mid packet")
            return

        yield Packet(ts_sec + ts_frac / ts_units, caplen, wirelen, linktype, data)


# --- pcapng ----------------------------------------------------------------

_SHB = 0x0A0D0D0A
_IDB = 0x00000001
_PB_OBSOLETE = 0x00000002
_SPB = 0x00000003
_EPB = 0x00000006

_BOM_BE = b"\x1a\x2b\x3c\x4d"
_BOM_LE = b"\x4d\x3c\x2b\x1a"

_OPT_END = 0
_OPT_IF_TSRESOL = 9


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    ts_units: int
    snaplen: int


def _iter_pcapng(fh: BinaryIO, strict: bool) -> Iterator[Packet]:
    endian: str | None = None
    interfaces: list[_Interface] = []

    while True:
        type_raw = fh.read(4)
        if not type_raw:
            return
        if len(type_raw) < 4:
            if strict:
                raise CaptureError("capture ends mid block header")
            return

        if type_raw == PCAPNG_MAGIC:
            # The section header block type is a byte palindrome, so it reads
            # identically in either byte order. The byte-order magic inside the
            # block is what actually establishes the section's endianness, and
            # a new section resets the interface table.
            len_raw, bom = fh.read(4), fh.read(4)
            if len(len_raw) < 4 or len(bom) < 4:
                if strict:
                    raise CaptureError("capture ends mid section header block")
                return
            if bom == _BOM_BE:
                endian = ">"
            elif bom == _BOM_LE:
                endian = "<"
            else:
                raise CaptureError(f"bad pcapng byte-order magic {bom.hex()}")

            total = struct.unpack(endian + "I", len_raw)[0]
            if not 28 <= total <= MAX_BLOCK_BYTES:
                raise CaptureError(f"implausible section header block length {total}")
            if len(fh.read(total - 12)) < total - 12:
                if strict:
                    raise CaptureError("capture ends mid section header block")
                return
            interfaces = []
            continue

        if endian is None:
            raise CaptureError("capture does not open with a section header block")

        block_type = struct.unpack(endian + "I", type_raw)[0]
        len_raw = fh.read(4)
        if len(len_raw) < 4:
            if strict:
                raise CaptureError("capture ends mid block header")
            return

        total = struct.unpack(endian + "I", len_raw)[0]
        if not 12 <= total <= MAX_BLOCK_BYTES:
            raise CaptureError(
                f"implausible length {total} for block type {block_type:#x}")

        body = fh.read(total - 12)
        trailer = fh.read(4)
        if len(body) < total - 12 or len(trailer) < 4:
            if strict:
                raise CaptureError("capture ends mid block")
            return

        if block_type == _IDB:
            if len(body) < 8:
                continue
            linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            options = _parse_options(body[8:], endian)
            interfaces.append(_Interface(linktype, _ts_units(options), snaplen))

        elif block_type == _EPB:
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
                endian + "IIIII", body, 0)
            packet = _packet(interfaces, iface_id, ts_hi, ts_lo,
                             caplen, wirelen, body, 20, strict)
            if packet is not None:
                yield packet

        elif block_type == _PB_OBSOLETE:
            if len(body) < 20:
                continue
            iface_id, _drops, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
                endian + "HHIIII", body, 0)
            packet = _packet(interfaces, iface_id, ts_hi, ts_lo,
                             caplen, wirelen, body, 20, strict)
            if packet is not None:
                yield packet

        elif block_type == _SPB:
            if len(body) < 4 or not interfaces:
                continue
            wirelen = struct.unpack_from(endian + "I", body, 0)[0]
            iface = interfaces[0]
            # A simple packet block stores no captured length of its own; it is
            # bounded by the block size and by the interface snaplen. It also
            # carries no timestamp, so periodicity analysis cannot use it.
            caplen = min(wirelen, len(body) - 4)
            if iface.snaplen:
                caplen = min(caplen, iface.snaplen)
            yield Packet(0.0, caplen, wirelen, iface.linktype, body[4:4 + caplen])


def _packet(interfaces: list[_Interface], iface_id: int, ts_hi: int, ts_lo: int,
            caplen: int, wirelen: int, body: bytes, offset: int,
            strict: bool) -> Packet | None:
    if not 0 <= iface_id < len(interfaces):
        if strict:
            raise CaptureError(f"packet references undeclared interface {iface_id}")
        return None
    iface = interfaces[iface_id]

    available = len(body) - offset
    if caplen > available:
        if strict:
            raise CaptureError("packet captured length exceeds its block")
        caplen = available

    ts = ((ts_hi << 32) | ts_lo) / iface.ts_units
    return Packet(ts, caplen, wirelen, iface.linktype, body[offset:offset + caplen])


def _parse_options(buf: bytes, endian: str) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, offset)
        offset += 4
        if code == _OPT_END:
            break
        if offset + length > len(buf):
            break
        options.setdefault(code, buf[offset:offset + length])
        offset += length + (-length % 4)  # options pad to a 4 byte boundary
    return options


def _ts_units(options: dict[int, bytes]) -> int:
    """Timestamp ticks per second for an interface, from pcapng if_tsresol.

    The high bit selects the base: clear means a power of ten, set means a
    power of two. Absent, the spec's default is microseconds.
    """
    raw = options.get(_OPT_IF_TSRESOL)
    if not raw:
        return 1_000_000
    value = raw[0]
    if value & 0x80:
        return 1 << (value & 0x7F)
    if value > 18:  # beyond attosecond resolution, treat as corrupt
        return 1_000_000
    return 10 ** value
