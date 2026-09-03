"""Packet decoding: a captured frame in, a Frame out.

decode() is the only entry point the rest of the tool needs, and the shared
types are re-exported here so detectors import one module rather than three.
"""

from __future__ import annotations

from ..pcap import Packet
from .inet import decode_ip
from .link import strip_link
from .types import (
    ETH_P_IPV4,
    ETH_P_IPV6,
    ETH_P_QINQ,
    ETH_P_VLAN,
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
    Flow,
    FlowKey,
    Frame,
)

__all__ = [
    "ETH_P_IPV4", "ETH_P_IPV6", "ETH_P_QINQ", "ETH_P_VLAN",
    "IPPROTO_ICMP", "IPPROTO_ICMPV6", "IPPROTO_TCP", "IPPROTO_UDP",
    "TCP_ACK", "TCP_FIN", "TCP_PSH", "TCP_RST", "TCP_SYN", "TCP_URG",
    "Flow", "FlowKey", "Frame",
    "decode", "decode_ip", "strip_link",
]


def decode(packet: Packet) -> Frame | None:
    """Decode one captured packet, or None if it carries no usable IP header."""
    stripped = strip_link(packet.linktype, packet.data)
    if stripped is None:
        return None
    ethertype, layer3, vlan = stripped
    return decode_ip(packet.ts, ethertype, layer3, packet.wirelen, vlan,
                     packet.truncated)
