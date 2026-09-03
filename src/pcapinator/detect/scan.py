"""Port and host scan detection over assembled flows.

Fan-out alone does not find scanners. A browser loading one page opens
connections to a hundred hosts on port 443 in a couple of seconds, which is the
exact shape of a horizontal sweep. What separates the two is what comes back: a
scan is a search for something that is not there, so most of its attempts end
with no session, while an ordinary client is talking to services it already
knows are up.

A candidate is therefore gated on two signals and only modulated by the rest:

  response      share of attempts that never reached a service. A packet coming
                back is not enough: a connect() scan of a live host is answered
                by a RST on every closed port, so counting a reply as an answer
                would miss the loudest scan there is. Neither is server payload
                enough on its own, because a whole class of ordinary traffic
                never carries any - a TCP health check, a bulk upload answered
                only by ACKs, a one-way UDP stream. An attempt counts as served
                when the responder sent data, when a TCP handshake completed and
                the responder kept talking past the single packet a refusal
                consists of, or when the client pushed more than a probe's worth
                of bytes, which nothing accepts on a port that is closed
  payload       share of attempts where the client sent no data. Probes carry a
                handshake and nothing else, so a fan-out where every attempt
                carried a transfer is a data push and not a search
  fan-out       distinct destination ports on one host (vertical) or distinct
                destination hosts on one port (horizontal), log scaled since the
                difference between 10 and 40 targets matters and the difference
                between 1000 and 4000 does not
  timing        connection rate and the uniformity of the gaps between
                connections; tools issue attempts faster and far more evenly
                than a person driving a client

The score multiplies the response and payload shares by the supporting signals,
so nothing with a healthy answer rate and nothing that moves real data can be
dragged over the threshold by being fast and wide. Timing is deliberately weak
support only: a scanner that paces itself to one connection every five seconds
is still a scanner, and rate is the one signal an attacker controls for free.

Shapes reported:

  VERTICAL      one source, one host, many ports
  HORIZONTAL    one source, one port, many hosts. Also covers an ICMP ping
                sweep, where the port is 0 for every flow
  HALF_OPEN     the stealth case, where the attempts are bare SYNs that were
                never answered at all. This is a property of the attempts
                rather than a third geometry, so the result still carries the
                host and port counts that say which way the sweep ran

Minimum fan-out is 10 distinct targets, and nothing below it is called a scan
whatever else it looks like. Under ten targets the geometry is ordinary: a mail
client touches a handful of ports on one server, a page load touches a handful
of hosts, and a client whose service died retries the same target forever with a
perfect response signal and no fan-out at all. Ten is also roughly the point
where the timing statistics stop being noise, since the median absolute
deviation of the gaps needs most of a dozen samples before it means anything.

Benign traffic deliberately tested against, in tests/test_scan.py:

  a browser opening a hundred connections to a hundred hosts on port 443
  a page load fanning out to CDN hosts inside a two second burst
  a backup job hammering one host and port with hundreds of connections
  a NAT gateway aggregating many users onto one source address
  a client retrying a service that is down, which is unanswered but not wide
  a mail client touching several ports on one server
  a load balancer TCP health checking every backend, which completes a
  handshake and carries no data in either direction
  a log shipper or backup client uploading to many storage nodes, answered only
  by bare ACKs, including one whose handshake predates the capture
  a one-way UDP stream fanning out to many multicast groups
  a server whose fragmented UDP replies form their own port-0 flows to every
  client it answers
  a management host waking a fleet with Wake-on-LAN, which is wide, fast, and
  answered by nothing at all
  a scanner and a browser in the same capture, where only the scanner is flagged

Known false positive classes this cannot separate on traffic shape alone:

  peer-to-peer clients bootstrapping. Contacting hundreds of peers from a stale
  peer list produces wide fan-out, no payload and almost no answers. It is a
  horizontal scan by every measure available here and is only distinguishable
  by knowing the application or the reputation of the destinations
  legitimate scanners. Monitoring probes, asset inventory and authorised
  vulnerability scans are scans; the detector is right and the analyst needs an
  allow list of sources
  a host coming back from an outage or sitting behind a captive portal, where
  every connection to every previously known host fails at once
  an empty TCP session torn down with a RST rather than a FIN, which leaves the
  same trace as a stealth probe of an open port: one packet back and no data.
  A health checker that aborts instead of closing lands here
  a router or firewall emitting ICMP errors, whether time-exceeded to a run of
  traceroutes or administratively-prohibited to every host it is blocking. A
  flow carries no ICMP type, so an error sent to forty hosts and an echo request
  sent to forty hosts are identical on every field there is, and the ping sweep
  is worth more than the false positive costs

What defeats it. The axes are per source, so an attacker who splits a sweep
across several sources, or who takes fewer than MIN_FANOUT ports from each host
and a different set per host, keeps every group under the floor and is not
reported. Rate limiting alone does not work, since timing is only support. And
a UDP sweep whose probes carry a protocol payload is scored as a data push and
missed: a Wake-on-LAN magic packet and an SNMP version probe are the same
hundred unanswered bytes sent wide, and a flow record holds nothing that tells
them apart. Empty probes, which is what a UDP port sweep sends to every port
there is no protocol probe for, are still caught.

A sweep of many hosts on many ports is reported twice, once per host as a
vertical result and once per port as a horizontal result. Both statements are
true and each is the answer to a different question, so neither is suppressed.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from itertools import chain
from typing import Iterable, Sequence

from ..layers.types import IPPROTO_TCP, TCP_ACK, TCP_RST, TCP_SYN, Flow

VERTICAL = "VERTICAL"
HORIZONTAL = "HORIZONTAL"
HALF_OPEN = "HALF_OPEN"

MIN_FANOUT = 10
# Fan-out at which the signal is saturated; more targets say nothing new.
FANOUT_FULL = 64.0
# A client that sent no more than this many bytes sent a handshake, not data.
PROBE_PAYLOAD = 64
# Client payload above this is a transfer rather than a probe: it sits above
# anything a scanner sends to elicit a UDP reply and below a session's first
# real write. Nothing accepts a transfer on a port that is closed.
SESSION_PAYLOAD = 1024
HALF_OPEN_RATIO = 0.8

# Connection rates bounding the timing signal, in connections per second.
SLOW_RATE = 0.2
FAST_RATE = 20.0
# Gaps closer together than this are treated as simultaneous, so uniformity is
# not decided by microsecond noise between back to back connections.
MIN_INTERVAL = 1e-3

# Captures are untrusted and a scan is the traffic most likely to blow a table
# up, so per-group state is bounded. Both limits sit far above the point where
# the signals they feed have saturated.
MAX_STARTS = 4096
MAX_TARGETS = 1 << 16

SUPPORT_FLOOR = 0.5
SUPPORT_FANOUT = 0.65
SUPPORT_TIMING = 0.35
# Payload gates like the response share, but with a floor: a scan that has to
# send a protocol probe to draw a UDP reply is still a scan.
PAYLOAD_FLOOR = 0.5
RATE_WEIGHT = 0.6


@dataclass(frozen=True, slots=True)
class Scan:
    kind: str
    src: str
    dst: str | None       # the swept host, for a vertical sweep
    dport: int | None     # the swept port, for a horizontal sweep
    proto: int
    hosts: int
    ports: int
    attempts: int
    fanout: int
    first: float
    last: float
    rate: float           # connection attempts per second
    fanout_score: float
    response_score: float
    timing_score: float
    payload_score: float
    half_open_ratio: float
    score: float

    @property
    def duration(self) -> float:
        return self.last - self.first

    def describe(self) -> str:
        target = f"{self.dst}" if self.dst is not None else f"port {self.dport}"
        reach = (f"{self.ports} ports" if self.dst is not None
                 else f"{self.hosts} hosts")
        return (f"{self.kind} {self.src} -> {target}: {reach} in "
                f"{self.attempts} attempts at {self.rate:.1f}/s "
                f"({self.response_score:.0%} unanswered, "
                f"score {self.score:.2f})")


def find_scans(flows: Iterable[Flow], *, threshold: float = 0.7,
               min_fanout: int = MIN_FANOUT) -> list[Scan]:
    """Score both sweep axes for every source and return the scans, worst first."""
    vertical: dict[tuple[int, str, str], _Group] = {}
    horizontal: dict[tuple[int, str, int], _Group] = {}

    for flow in flows:
        key = flow.key
        down = vertical.get((key.proto, key.src, key.dst))
        if down is None:
            down = _Group(key.proto, key.src, key.dst, None)
            vertical[(key.proto, key.src, key.dst)] = down
        down.add(flow, key.dport)

        across = horizontal.get((key.proto, key.src, key.dport))
        if across is None:
            across = _Group(key.proto, key.src, None, key.dport)
            horizontal[(key.proto, key.src, key.dport)] = across
        across.add(flow, key.dst)

    found = []
    for group in chain(vertical.values(), horizontal.values()):
        scan = group.score(min_fanout)
        if scan is not None and scan.score >= threshold:
            found.append(scan)
    found.sort(key=lambda s: (s.score, s.fanout, s.attempts), reverse=True)
    return found


@dataclass(slots=True)
class _Group:
    """Running totals for one source and one sweep axis."""

    proto: int
    src: str
    dst: str | None
    dport: int | None
    targets: set[object] = field(default_factory=set)
    attempts: int = 0
    served: int = 0
    stealth: int = 0
    quiet: int = 0
    starts: list[float] = field(default_factory=list)

    def add(self, flow: Flow, target: object) -> None:
        if len(self.targets) < MAX_TARGETS:
            self.targets.add(target)
        self.attempts += 1
        if _served(flow):
            self.served += 1
        if not flow.responded and _is_bare_syn(flow):
            self.stealth += 1
        if flow.payload_out <= PROBE_PAYLOAD:
            self.quiet += 1
        if len(self.starts) < MAX_STARTS:
            self.starts.append(flow.start)

    def score(self, min_fanout: int) -> Scan | None:
        fanout = len(self.targets)
        if fanout < min_fanout or self.attempts == 0:
            return None

        response = 1.0 - self.served / self.attempts
        payload = self.quiet / self.attempts
        half_open = self.stealth / self.attempts
        fanout_score = _clamp(math.log(fanout) / math.log(FANOUT_FULL))
        rate, timing = _timing(self.starts)

        support = SUPPORT_FANOUT * fanout_score + SUPPORT_TIMING * timing
        score = (response
                 * (PAYLOAD_FLOOR + (1.0 - PAYLOAD_FLOOR) * payload)
                 * (SUPPORT_FLOOR + (1.0 - SUPPORT_FLOOR) * support))

        if half_open >= HALF_OPEN_RATIO:
            kind = HALF_OPEN
        else:
            kind = VERTICAL if self.dst is not None else HORIZONTAL

        return Scan(
            kind=kind, src=self.src, dst=self.dst, dport=self.dport,
            proto=self.proto,
            hosts=1 if self.dst is not None else fanout,
            ports=fanout if self.dst is not None else 1,
            attempts=self.attempts,
            fanout=fanout,
            first=min(self.starts),
            last=max(self.starts),
            rate=rate,
            fanout_score=fanout_score,
            response_score=response,
            timing_score=timing,
            payload_score=payload,
            half_open_ratio=half_open,
            score=score,
        )


def _served(flow: Flow) -> bool:
    """Whether the attempt reached a service rather than bouncing off a port.

    Three outcomes have to be told apart. A reply carrying data is plainly a
    served session. A bare reset is a refusal, the loud half of a connect scan,
    and a lone SYN-ACK is what a stealth probe of an open port draws; neither
    counts. Between them sits the connection that completed and carried nothing,
    which counts, because requiring returned data makes a whole class of
    ordinary traffic look maximally scan-like: a TCP health check, a bulk upload
    answered only by ACKs, any protocol whose server does not speak first.

    Client payload is the other way in. Nothing accepts a transfer on a port
    that is closed, so a large enough push is proof of service on its own, which
    is what covers one-way UDP and a TCP session whose handshake happened before
    the capture started.
    """
    if flow.payload_in > 0 or flow.payload_out > SESSION_PAYLOAD:
        return True
    if flow.key.proto != IPPROTO_TCP:
        return False
    handshake = TCP_SYN | TCP_ACK
    return (flow.flags_seen & (handshake | TCP_RST) == handshake
            and flow.packets_in >= 2)


def _is_bare_syn(flow: Flow) -> bool:
    """A TCP attempt that got as far as a SYN and no further.

    Retransmitted SYNs leave the same trace as one SYN, which is why the test is
    on the flags seen rather than on the packet count.
    """
    if flow.key.proto != IPPROTO_TCP:
        return False
    return bool(flow.flags_seen & TCP_SYN) and not flow.flags_seen & (TCP_ACK | TCP_RST)


def _timing(starts: Sequence[float]) -> tuple[float, float]:
    """Connection rate and how evenly the attempts were spaced."""
    ordered = sorted(starts)
    span = ordered[-1] - ordered[0]
    rate = (len(ordered) - 1) / span if span > 0 else math.inf
    intervals = [b - a for a, b in zip(ordered, ordered[1:])]
    timing = (RATE_WEIGHT * _rate_score(rate)
              + (1.0 - RATE_WEIGHT) * _uniformity(intervals))
    return rate, timing


def _rate_score(rate: float) -> float:
    # Written as bounds rather than a clamped logarithm so an infinite rate,
    # which is what simultaneous attempts produce, stays in range.
    if not rate > 0:
        return 0.0
    if rate >= FAST_RATE:
        return 1.0
    if rate <= SLOW_RATE:
        return 0.0
    return math.log(rate / SLOW_RATE) / math.log(FAST_RATE / SLOW_RATE)


def _uniformity(intervals: Sequence[float]) -> float:
    """Evenness of the gaps, on 0 to 1, measured robustly.

    Median absolute deviation rather than variance: one pause in the middle of a
    scan must not undo the evidence from every other gap.
    """
    if not intervals:
        return 0.0
    center = statistics.median(intervals)
    mad = statistics.median([abs(value - center) for value in intervals])
    return _clamp(1.0 - mad / max(center, MIN_INTERVAL))


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
