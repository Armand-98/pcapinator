"""IPv4/IPv6 and transport decoding, from layer 3 bytes to a Frame.

Everything here reads attacker-controlled bytes. A length taken from the wire is
only used after it has been checked against what was actually captured, a slice
is never taken past the buffer, and anything malformed returns None rather than
raising.

A packet whose transport header is absent is still described rather than
dropped, because a fragment or an unusual protocol number is itself signal.
"""

from __future__ import annotations

import socket
import struct

from .types import (
    ETH_P_IPV4,
    ETH_P_IPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    Frame,
)

IPV4_MIN_HDR_LEN = 20
IPV6_HDR_LEN = 40
TCP_MIN_HDR_LEN = 20
UDP_HDR_LEN = 8

IPPROTO_HOPOPTS = 0
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_AH = 51
IPPROTO_DSTOPTS = 60

# Extension headers measured in 8 byte units beyond the first 8.
_EXT_HEADERS = frozenset((IPPROTO_HOPOPTS, IPPROTO_ROUTING, IPPROTO_DSTOPTS))
_CHAIN_HEADERS = _EXT_HEADERS | {IPPROTO_AH, IPPROTO_FRAGMENT}

# RFC 8200 puts no limit on chain length, so a crafted packet could chain
# headers until the buffer runs out. Real traffic uses one or two.
MAX_EXT_HEADERS = 8


def decode_ip(ts: float, ethertype: int, data: bytes, wirelen: int,
              vlan: int | None = None, truncated: bool = False) -> Frame | None:
    """Decode layer 3 bytes into a Frame, or None if they are not usable."""
    if ethertype == ETH_P_IPV4:
        return _ipv4(ts, data, wirelen, vlan, truncated)
    if ethertype == ETH_P_IPV6:
        return _ipv6(ts, data, wirelen, vlan, truncated)
    return None


def _ipv4(ts: float, data: bytes, wirelen: int, vlan: int | None,
          truncated: bool) -> Frame | None:
    if len(data) < IPV4_MIN_HDR_LEN or data[0] >> 4 != 4:
        return None

    ihl = data[0] & 0x0F
    if ihl < 5:
        return None
    hdr_len = ihl * 4

    total_len = struct.unpack_from("!H", data, 2)[0]
    if hdr_len <= total_len < len(data):
        # Bytes past total length are link padding, not payload. A total length
        # beyond what was captured just means the capture was cut short.
        data = data[:total_len]
    if len(data) < hdr_len:
        return None

    frag_field = struct.unpack_from("!H", data, 6)[0]
    frag_offset = frag_field & 0x1FFF
    more_fragments = bool(frag_field & 0x2000)

    ttl = data[8]
    proto = data[9]
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])

    if frag_offset:
        # Past the first fragment these bytes are payload continuation, so
        # reading a transport header here would invent ports out of user data.
        return Frame(ts=ts, src=src, dst=dst, proto=proto, sport=0, dport=0,
                     payload=b"", wirelen=wirelen, ip_version=4, ttl=ttl,
                     vlan=vlan, fragmented=True, truncated=truncated)

    return _transport(ts, src, dst, proto, data[hdr_len:], wirelen, 4, ttl, vlan,
                      more_fragments, truncated)


def _ipv6(ts: float, data: bytes, wirelen: int, vlan: int | None,
          truncated: bool) -> Frame | None:
    if len(data) < IPV6_HDR_LEN or data[0] >> 4 != 6:
        return None

    payload_len = struct.unpack_from("!H", data, 4)[0]
    next_header = data[6]
    ttl = data[7]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    # Zero means a jumbogram whose real length lives in a hop-by-hop option, so
    # it is not a trim instruction.
    if payload_len and IPV6_HDR_LEN + payload_len < len(data):
        data = data[:IPV6_HDR_LEN + payload_len]

    offset = IPV6_HDR_LEN
    fragmented = False
    depth = 0

    while next_header in _CHAIN_HEADERS:
        depth += 1
        if depth > MAX_EXT_HEADERS or offset + 2 > len(data):
            return None

        if next_header == IPPROTO_FRAGMENT:
            fragmented = True
            if offset + 8 > len(data):
                return None
            frag_offset = struct.unpack_from("!H", data, offset + 2)[0] >> 3
            if frag_offset:
                return Frame(ts=ts, src=src, dst=dst, proto=data[offset], sport=0,
                             dport=0, payload=b"", wirelen=wirelen, ip_version=6,
                             ttl=ttl, vlan=vlan, fragmented=True,
                             truncated=truncated)
            ext_len = 8
        elif next_header == IPPROTO_AH:
            # RFC 4302 counts AH in 4 byte units and excludes the first 8 bytes.
            ext_len = (data[offset + 1] + 2) * 4
        else:
            ext_len = (data[offset + 1] + 1) * 8

        if offset + ext_len > len(data):
            return None
        next_header, offset = data[offset], offset + ext_len

    return _transport(ts, src, dst, next_header, data[offset:], wirelen, 6, ttl,
                      vlan, fragmented, truncated)


def _transport(ts: float, src: str, dst: str, proto: int, rest: bytes, wirelen: int,
               ip_version: int, ttl: int, vlan: int | None, fragmented: bool,
               truncated: bool) -> Frame | None:
    sport = dport = flags = 0
    payload = rest   # ICMP and anything without ports keep the whole remainder

    if proto == IPPROTO_TCP:
        if len(rest) < TCP_MIN_HDR_LEN:
            return None
        data_offset = rest[12] >> 4
        if data_offset < 5:
            return None
        hdr_len = data_offset * 4
        sport, dport = struct.unpack_from("!HH", rest, 0)
        flags = rest[13]
        # A snaplen can cut the options short; the ports and flags ahead of the
        # cut are still worth reporting, so only the payload is given up.
        payload = rest[hdr_len:] if hdr_len <= len(rest) else b""

    elif proto == IPPROTO_UDP:
        if len(rest) < UDP_HDR_LEN:
            return None
        sport, dport, udp_len = struct.unpack_from("!HHH", rest, 0)
        payload = rest[UDP_HDR_LEN:]
        if udp_len >= UDP_HDR_LEN:
            payload = payload[:udp_len - UDP_HDR_LEN]

    return Frame(ts=ts, src=src, dst=dst, proto=proto, sport=sport, dport=dport,
                 payload=payload, wirelen=wirelen, flags=flags,
                 ip_version=ip_version, ttl=ttl, vlan=vlan, fragmented=fragmented,
                 truncated=truncated)
