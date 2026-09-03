"""Decoded packet and flow types shared across the tool.

Detectors depend on this module rather than on any individual protocol decoder,
so a new link type or transport can be added without touching detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

ETH_P_IPV4 = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded packet, flattened to the fields detection actually uses."""

    ts: float
    src: str
    dst: str
    proto: int
    sport: int          # 0 for protocols without ports
    dport: int
    payload: bytes      # transport payload, above the TCP/UDP header
    wirelen: int        # whole frame length on the wire
    flags: int = 0      # TCP flags, 0 otherwise
    ip_version: int = 4
    ttl: int = 0
    vlan: int | None = None
    fragmented: bool = False
    truncated: bool = False   # capture stored less than the wire carried

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & TCP_SYN) and not self.flags & TCP_ACK

    @property
    def is_synack(self) -> bool:
        return bool(self.flags & TCP_SYN) and bool(self.flags & TCP_ACK)


@dataclass(frozen=True, slots=True)
class FlowKey:
    """A conversation, oriented initiator first.

    Both directions of a conversation map to one key. Orientation is taken from
    the TCP SYN where there is one, and otherwise from whichever endpoint was
    seen first, so beaconing analysis can reason about who is calling out.
    """

    proto: int
    src: str
    sport: int
    dst: str
    dport: int

    @property
    def endpoints(self) -> tuple[str, str, int]:
        """Identity a beacon is tracked by: who talks to what service."""
        return (self.src, self.dst, self.dport)


@dataclass(slots=True)
class Flow:
    key: FlowKey
    start: float
    end: float
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    payload_out: int = 0
    payload_in: int = 0
    flags_seen: int = 0
    responded: bool = False   # the responder sent at least one packet back

    @property
    def duration(self) -> float:
        return self.end - self.start

    @property
    def packets(self) -> int:
        return self.packets_out + self.packets_in

    @property
    def bytes(self) -> int:
        return self.bytes_out + self.bytes_in
