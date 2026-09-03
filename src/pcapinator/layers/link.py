"""Link layer stripping: from a captured frame to its network layer bytes.

Each supported link type is reduced to the same answer, an ethertype plus the
layer 3 slice, so the IP decoder never has to know how the frame was captured.

Frames are untrusted. Every header is length checked before it is sliced, and
the VLAN tag walk is depth capped so a frame built entirely of tags cannot spin.
"""

from __future__ import annotations

import struct

from ..pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
)
from .types import ETH_P_IPV4, ETH_P_IPV6, ETH_P_QINQ, ETH_P_VLAN

ETH_HDR_LEN = 14
SLL_HDR_LEN = 16
SLL2_HDR_LEN = 20
NULL_HDR_LEN = 4
VLAN_TAG_LEN = 4

# 0x9100 predates 802.1ad and is still emitted by some carrier gear.
_VLAN_TPIDS = (ETH_P_VLAN, ETH_P_QINQ, 0x9100)

# Deeper than any real deployment stacks tags, shallow enough that a frame made
# only of tags is rejected rather than walked.
MAX_VLAN_TAGS = 4

AF_INET = 2
# The BSD loopback family number for IPv6 differs per OS that wrote the capture:
# 24 on Linux/older BSD, 28 on FreeBSD, 30 on macOS.
AF_INET6_VALUES = frozenset((24, 28, 30))


def strip_link(linktype: int, data: bytes) -> tuple[int, bytes, int | None] | None:
    """Return (ethertype, layer 3 bytes, outermost VLAN id) for an IP frame.

    None means the frame is too short, the link type is not one we decode, or it
    carries something other than IPv4/IPv6 (ARP, LLDP, 802.3 LLC and so on).
    """
    if linktype == LINKTYPE_ETHERNET:
        return _ethernet(data)
    if linktype == LINKTYPE_LINUX_SLL:
        return _fixed(data, SLL_HDR_LEN, 14)
    if linktype == LINKTYPE_LINUX_SLL2:
        return _fixed(data, SLL2_HDR_LEN, 0)
    if linktype == LINKTYPE_NULL:
        return _loopback(data)
    if linktype == LINKTYPE_RAW:
        return _bare(data, _version_ethertype(data))
    if linktype == LINKTYPE_IPV4:
        return _bare(data, ETH_P_IPV4)
    if linktype == LINKTYPE_IPV6:
        return _bare(data, ETH_P_IPV6)
    return None


def _ethernet(data: bytes) -> tuple[int, bytes, int | None] | None:
    if len(data) < ETH_HDR_LEN:
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    offset = ETH_HDR_LEN
    vlan: int | None = None

    for _ in range(MAX_VLAN_TAGS):
        if ethertype not in _VLAN_TPIDS:
            break
        if offset + VLAN_TAG_LEN > len(data):
            return None
        tci, ethertype = struct.unpack_from("!HH", data, offset)
        if vlan is None:
            vlan = tci & 0x0FFF   # the outermost tag identifies the segment
        offset += VLAN_TAG_LEN
    else:
        if ethertype in _VLAN_TPIDS:
            return None

    return _bare(data[offset:], ethertype, vlan)


def _fixed(data: bytes, hdr_len: int, proto_offset: int
           ) -> tuple[int, bytes, int | None] | None:
    if len(data) < hdr_len:
        return None
    ethertype = struct.unpack_from("!H", data, proto_offset)[0]
    return _bare(data[hdr_len:], ethertype)


def _loopback(data: bytes) -> tuple[int, bytes, int | None] | None:
    """BSD loopback: a 4 byte address family in the writing host's byte order.

    There is no byte order marker, so both readings are tried and the one that
    names a known family wins. Real family numbers are small, which makes the
    wrong-endian reading of any of them far too large to collide.
    """
    if len(data) < NULL_HDR_LEN:
        return None
    for endian in ("<", ">"):
        family = struct.unpack_from(endian + "I", data, 0)[0]
        if family == AF_INET:
            return _bare(data[NULL_HDR_LEN:], ETH_P_IPV4)
        if family in AF_INET6_VALUES:
            return _bare(data[NULL_HDR_LEN:], ETH_P_IPV6)
    return None


def _version_ethertype(data: bytes) -> int:
    """LINKTYPE_RAW carries no protocol field; the IP version nibble is it."""
    if not data:
        return 0
    version = data[0] >> 4
    if version == 4:
        return ETH_P_IPV4
    if version == 6:
        return ETH_P_IPV6
    return 0


def _bare(payload: bytes, ethertype: int, vlan: int | None = None
          ) -> tuple[int, bytes, int | None] | None:
    if not payload or ethertype not in (ETH_P_IPV4, ETH_P_IPV6):
        return None
    return ethertype, payload, vlan
