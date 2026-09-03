"""DNS activity lifted out of a frame stream.

Both DNS detectors work on the same view of a capture: who asked what, when, and
what came back. Extracting that once keeps the tunneling and DGA detectors free
of transport handling and means they agree on what a query was.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from .layers.dns import parse_dns, parse_dns_tcp
from .layers.types import IPPROTO_TCP, IPPROTO_UDP, Frame

DNS_PORTS = (53, 5353)


@dataclass(frozen=True, slots=True)
class DnsEvent:
    ts: float
    client: str
    server: str
    name: str
    qtype: int
    rcode: int
    is_response: bool

    @property
    def labels(self) -> list[str]:
        """Query labels, root label dropped.

        A label may itself contain a literal dot byte, so this cannot recover
        the exact wire labels of a hostile name. Detectors must treat it as a
        view of the name rather than as ground truth about its structure.
        """
        return [label for label in self.name.split(".") if label]

    @property
    def parent(self) -> str:
        """The registrable-looking suffix a query hangs off.

        Tunnels encode data in the leftmost labels and keep a fixed suffix, so
        grouping on the last two labels collects a tunnel's traffic together.
        """
        labels = self.labels
        return ".".join(labels[-2:]) if len(labels) >= 2 else self.name


def dns_event(frame: Frame, *,
              ports: tuple[int, ...] = DNS_PORTS) -> DnsEvent | None:
    """Lift one frame to a DNS event, or None if it carries no DNS query."""
    if frame.sport not in ports and frame.dport not in ports:
        return None
    if frame.proto == IPPROTO_UDP:
        message = parse_dns(frame.payload)
    elif frame.proto == IPPROTO_TCP:
        message = parse_dns_tcp(frame.payload)
    else:
        return None
    if message is None or not message.questions:
        return None

    question = message.questions[0]
    # On the way back the addresses are reversed but the client is still the
    # client, which is what grouping by client depends on.
    client, server = ((frame.dst, frame.src) if message.is_response
                      else (frame.src, frame.dst))
    return DnsEvent(
        ts=frame.ts,
        client=client,
        server=server,
        name=question.name,
        qtype=question.qtype,
        rcode=message.rcode,
        is_response=message.is_response,
    )


def dns_events(frames: Iterable[Frame], *,
               ports: tuple[int, ...] = DNS_PORTS) -> Iterator[DnsEvent]:
    for frame in frames:
        event = dns_event(frame, ports=ports)
        if event is not None:
            yield event
