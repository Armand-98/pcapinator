"""C2 beaconing detection.

Command and control implants call home on a schedule. Looking for identical
intervals does not find them: every real framework jitters its callbacks, and an
implant on a laptop misses check-ins whenever the host sleeps.

A conversation is therefore scored on four independent signals, so no single one
has to be conclusive:

  interval regularity   dispersion of callback intervals measured by median
                        absolute deviation, which unlike standard deviation is
                        not dragged around by one long outage
  interval symmetry     Bowley skewness of the interval distribution; scheduled
                        traffic is symmetric about its period, human driven
                        traffic is heavily right skewed
  payload consistency   implant check-ins carry near identical amounts of data,
                        real sessions vary widely
  schedule coverage     how much of the capture the conversation spans, which
                        separates a beacon from a short burst that happened to
                        look regular

Missed check-ins are folded onto the estimated base period: an implant calling
home every 60s that misses two callbacks produces a 180s gap, which is evidence
for the schedule rather than against it.

Folding has to be constrained or it proves nothing. Given a free choice of
integer multiple per gap, any set of intervals can be folded onto some small
period, which is the submultiple degeneracy familiar from pitch detection. Two
constraints remove it: a gap only counts as missed check-ins when it lands
within FOLD_TOLERANCE of an exact multiple, and among candidate periods that fit
equally well the largest is chosen, since every submultiple of a true period
fits anything the period itself does.

WHAT THE SCORE MEANS. It measures how strongly traffic is scheduled, not how
malicious it is, and the two must not be conflated. A monitoring system polling
a service every ten seconds scores higher than most real implants, because it is
a more perfect beacon. No timing statistic can separate the two: they are the
same signal. Ranking and triage therefore belong to the reporting layer, which
has the context timing lacks, and the destination scope recorded on each result
is the first piece of that context. Suppressing internal destinations here would
hide lateral movement, so nothing is suppressed.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..layers.types import Flow

MIN_CONNECTIONS = 8
# A gap wider than this many periods is an outage, not a run of missed
# check-ins, and folding it would manufacture agreement that is not there.
MAX_FOLD = 6
# How far off an exact multiple a gap may land and still count as missed
# check-ins rather than as evidence against the schedule.
FOLD_TOLERANCE = 0.35
# Candidate periods below this fraction of the shortest observed interval are
# not considered; nothing in the data supports them.
MIN_PERIOD_FRACTION = 0.5
# Scoring more candidate periods than this stops being informative and starts
# being quadratic.
MAX_CANDIDATE_DELTAS = 300

# Interval regularity gates the verdict rather than being averaged into it: a
# conversation with irregular timing is not a beacon however consistent its
# payloads look. The supporting signals modulate within this floor.
SUPPORT_FLOOR = 0.6

SUPPORT_SKEW = 0.20
SUPPORT_SIZE = 0.40
SUPPORT_COVERAGE = 0.40


@dataclass(frozen=True, slots=True)
class Beacon:
    src: str
    dst: str
    dport: int
    proto: int
    dst_scope: str
    connections: int
    period: float
    jitter: float
    missed: int
    bytes_out: int
    first: float
    last: float
    interval_score: float
    skew_score: float
    size_score: float
    coverage_score: float
    score: float

    @property
    def duration(self) -> float:
        return self.last - self.first

    def describe(self) -> str:
        return (f"{self.src} -> {self.dst}:{self.dport} [{self.dst_scope}] every "
                f"{self.period:.1f}s +/-{self.jitter:.1f}s "
                f"({self.connections} connections, score {self.score:.2f})")


def find_beacons(flows: Iterable[Flow], *, threshold: float = 0.7,
                 min_connections: int = MIN_CONNECTIONS,
                 local_nets: Sequence = ()) -> list[Beacon]:
    """Score every conversation and return those that look scheduled, worst first."""
    grouped: dict[tuple[str, str, int, int], list[Flow]] = defaultdict(list)
    for flow in flows:
        key = flow.key
        grouped[(key.src, key.dst, key.dport, key.proto)].append(flow)

    window = _capture_window(grouped.values())

    found = []
    for (src, dst, dport, proto), group in grouped.items():
        beacon = score_group(src, dst, dport, proto, group, window,
                             min_connections=min_connections,
                             local_nets=local_nets)
        if beacon is not None and beacon.score >= threshold:
            found.append(beacon)
    found.sort(key=lambda b: b.score, reverse=True)
    return found


def score_group(src: str, dst: str, dport: int, proto: int,
                flows: Sequence[Flow], window: float, *,
                min_connections: int = MIN_CONNECTIONS,
                local_nets: Sequence = ()) -> Beacon | None:
    if len(flows) < min_connections:
        return None

    starts = sorted(flow.start for flow in flows)
    deltas = [b - a for a, b in zip(starts, starts[1:]) if b - a > 0]
    if len(deltas) < min_connections - 1:
        return None

    fit = _best_fit(deltas)
    if fit is None:
        return None

    skew_score = _clamp(1.0 - abs(_bowley_skew(fit.folded)))
    size_score = _consistency([flow.payload_out for flow in flows])
    span = starts[-1] - starts[0]
    coverage_score = _clamp(span / window) if window > 0 else 0.0

    support = (SUPPORT_SKEW * skew_score
               + SUPPORT_SIZE * size_score
               + SUPPORT_COVERAGE * coverage_score)
    score = fit.quality * (SUPPORT_FLOOR + (1.0 - SUPPORT_FLOOR) * support)

    return Beacon(
        src=src, dst=dst, dport=dport, proto=proto,
        dst_scope=scope(dst, local_nets),
        connections=len(flows),
        period=fit.period,
        jitter=fit.deviation,
        missed=fit.missed,
        bytes_out=sum(flow.bytes_out for flow in flows),
        first=starts[0],
        last=starts[-1],
        interval_score=fit.quality,
        skew_score=skew_score,
        size_score=size_score,
        coverage_score=coverage_score,
        score=score,
    )


@dataclass(frozen=True, slots=True)
class _Fit:
    period: float
    folded: list[float]
    missed: int
    deviation: float    # typical distance from the period, in seconds
    agreement: float    # share of gaps the schedule explains
    quality: float


def _best_fit(deltas: Sequence[float]) -> _Fit | None:
    """Choose the period that best explains the observed gaps.

    Candidates are drawn from the data itself: each observed gap divided by each
    plausible number of missed check-ins. Ties break toward the larger period,
    because every submultiple of a true period explains the data exactly as well
    and would otherwise win simply by being tried.
    """
    ordered = sorted(deltas)
    floor = ordered[0] * MIN_PERIOD_FRACTION
    if floor <= 0:
        return None

    candidates = {delta / multiple
                  for delta in _sample(ordered, MAX_CANDIDATE_DELTAS)
                  for multiple in range(1, MAX_FOLD + 1)
                  if delta / multiple >= floor}

    best: _Fit | None = None
    for period in sorted(candidates, reverse=True):
        fit = _fit(deltas, period)
        if fit is None:
            continue
        if best is None or fit.quality > best.quality + 1e-9:
            best = fit
    return best


def _fit(deltas: Sequence[float], period: float) -> _Fit | None:
    """Fold gaps onto one period, keeping only those a schedule would produce."""
    folded: list[float] = []
    missed = 0
    for delta in deltas:
        multiple = round(delta / period)
        if not 1 <= multiple <= MAX_FOLD:
            continue
        if abs(delta - multiple * period) > FOLD_TOLERANCE * period:
            continue
        folded.append(delta / multiple)
        missed += multiple - 1
    if not folded:
        return None

    agreement = len(folded) / len(deltas)
    # Deviation is measured against the candidate period, not against the
    # folded values' own median. Measured against their median, a wrong period
    # scores perfectly whenever the folded values agree with each other while
    # all disagreeing with the period by the same amount.
    deviation = _deviation(folded, period)
    return _Fit(period, folded, missed, deviation, agreement,
                _clamp(1.0 - deviation / period) * agreement)


def _sample(ordered: Sequence[float], limit: int) -> list[float]:
    if len(ordered) <= limit:
        return list(ordered)
    step = len(ordered) / limit
    return [ordered[int(index * step)] for index in range(limit)]


def _consistency(values: Sequence[int]) -> float:
    """How tightly a set of payload sizes clusters, on 0 to 1."""
    if not values:
        return 0.0
    center = statistics.median(values)
    if center <= 0:
        # Every check-in carried an empty payload, which is itself consistent.
        return 1.0 if all(v == 0 for v in values) else 0.0
    return _clamp(1.0 - _mad(values) / center)


def _bowley_skew(values: Sequence[float]) -> float:
    """Quartile based skewness, bounded to -1..1 and robust to outliers."""
    ordered = sorted(values)
    q1 = _quantile(ordered, 0.25)
    q2 = _quantile(ordered, 0.50)
    q3 = _quantile(ordered, 0.75)
    spread = q3 - q1
    if spread <= 0:
        return 0.0
    return (q3 + q1 - 2 * q2) / spread


def _deviation(folded: Sequence[float], period: float) -> float:
    return statistics.median([abs(value - period) for value in folded])


def _mad(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    center = statistics.median(values)
    return statistics.median([abs(v - center) for v in values])


def _quantile(ordered: Sequence[float], q: float) -> float:
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return float(ordered[0])
    position = q * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def _capture_window(groups: Iterable[Sequence[Flow]]) -> float:
    first = last = None
    for group in groups:
        for flow in group:
            if first is None or flow.start < first:
                first = flow.start
            if last is None or flow.end > last:
                last = flow.end
    if first is None or last is None:
        return 0.0
    return last - first


# Ranges that mean "inside this organisation". Deliberately narrower than
# ipaddress.is_private, which also covers the documentation and benchmarking
# ranges; those stand in for public address space and a schedule to one is an
# external schedule, not an internal one.
_INTERNAL = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "100.64.0.0/10",                                    # RFC 6598 carrier NAT
    "fc00::/7",                                         # RFC 4193 unique local
))


def scope(address: str, local_nets: Sequence = ()) -> str:
    """Classify a destination so a report can rank findings that timing cannot.

    A schedule reaching outside the network deserves an analyst's attention
    before an identical schedule to a host on their own subnet.

    local_nets overrides the default ranges, because "inside" is a property of
    the deployment and not of the address. A capture taken on an internet facing
    server has no RFC 1918 addresses in it at all, and every address in it is
    external by the default rule, which is exactly backwards.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_link_local:
        return "link-local"
    networks = local_nets or _INTERNAL
    if any(parsed in network for network in networks
           if network.version == parsed.version):
        return "private"
    return "external"


def is_local(address: str, local_nets: Sequence) -> bool:
    """Whether an address belongs to the network the analyst declared as theirs."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in local_nets
               if network.version == parsed.version)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
