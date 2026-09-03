"""DNS tunneling and exfiltration detection.

A tunnel turns the resolver into a transport: data is encoded into the leftmost
labels of a query, a nameserver the attacker controls answers, and the payload
comes back in the answer. The traffic that results is high cardinality, but so
is a CDN's, so cardinality alone convicts nothing.

The one property a tunnel cannot give up is that its query names must *carry*
the data. That is measured directly, as information capacity per query:

  varying labels    only the labels that actually vary across a parent domain
                    are scored. Labels that are constant in that position for
                    nearly every query are routing, not payload, which is what
                    strips "blob.core" off an Azure hostname and the fixed
                    prefix off a tunnel alike
  name length       encoded payload makes the varying part far longer than a
                    hostname anyone would type
  Shannon entropy   per character, over the varying labels. base32/base64 data
                    sits near 5 bits, hex near 4, real hostnames near 3
  capacity          length * entropy, the bits a query can smuggle. This is the
                    discriminant: a 16 character CDN hash carries ~60 bits, a
                    single base32 label carries ~300

Capacity gates the verdict, scaled by how nearly unique the subdomains are, and
the supporting signals modulate it within SUPPORT_FLOOR:

  query type skew   TXT, NULL and CNAME carry the most data back
  NXDOMAIN ratio    high for tunnels whose server answers out of band, and
                    unknown rather than zero when no responses were captured
  query rate        and how much of the capture the activity is sustained over
  upload volume     estimated bytes encoded in query names, which is the number
                    an incident responder actually wants

Estimated upload is information theoretic, sum(len * entropy) / 8, rather than
assuming an encoding, so it stays a lower bound for base32 and base64 alike.

Benign patterns deliberately tested against (tests/test_dnstunnel.py):

  CDN and cloud hostnames    thousands of unique hex or GUID hostnames under
                             one parent. Cardinality is maximal, capacity is
                             not: the names are short and drawn from a small
                             alphabet
  reverse DNS sweeps         .arpa parents are excluded outright. Their labels
                             are numeric and structurally constrained, so they
                             are not an exfiltration channel; scoring them
                             would only produce noise on any subnet sweep
  DGA traffic                one query per registered domain, so a DGA never
                             reaches MIN_QUERIES under a shared parent. Also
                             tested for DGAs hung off a dynamic DNS parent,
                             where the label is short and low capacity
  antivirus/reputation       MD5 and SHA-1 lookups encoding a hash per query,
                             over TXT, answered NXDOMAIN
  long descriptive names     long but low entropy, and queried repeatedly

Known limitation: reputation services that encode a SHA-256 into one label are
not separable from a tunnel by content. 64 hex characters is ~250 bits per
query, the same capacity as a real tunnel, sent to a fixed parent at a steady
rate. Separating those needs a domain allowlist, which is deployment data and
deliberately not baked in here.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..dnsview import DnsEvent
from ..layers.dns import QTYPE_CNAME, QTYPE_NULL, QTYPE_TXT, RCODE_NXDOMAIN

MIN_QUERIES = 12
MIN_UNIQUE = 8

DATA_QTYPES = frozenset({QTYPE_TXT, QTYPE_NULL, QTYPE_CNAME})

# Bits per query below which the name cannot be carrying meaningful payload,
# and above which it is carrying as much as a tunnel bothers to send.
BITS_FLOOR = 90.0
BITS_CEIL = 240.0
# Under this, the varying labels are not encoded data: numeric, dictionary or
# too short to be anything else.
ENTROPY_FLOOR = 3.3

# Distinct subdomains per query. Benign clients revisit names; a tunnel cannot.
UNIQUE_FLOOR = 0.40
UNIQUE_SPAN = 0.50

# Share of queries a label position must agree on to count as routing rather
# than payload.
CONSTANT_SHARE = 0.90
MAX_CONSTANT_DEPTH = 8

RATE_CEIL = 5.0          # queries/second that saturates the rate signal
VOLUME_CEIL = 4096.0     # estimated upload bytes that saturates the volume signal

# Capacity gates the verdict rather than being averaged into it: no amount of
# rate or TXT skew makes a short low entropy name into a tunnel.
SUPPORT_FLOOR = 0.65
SUPPORT_QTYPE = 0.30
SUPPORT_NXDOMAIN = 0.20
SUPPORT_RATE = 0.20
SUPPORT_SUSTAIN = 0.15
SUPPORT_VOLUME = 0.15

# Untrusted-input bounds: a capture can name anything it likes.
MAX_DOMAINS = 50_000
MAX_RECORDS_PER_DOMAIN = 20_000
MAX_ENCODED_CHARS = 512
SAMPLES = 5


@dataclass(frozen=True, slots=True)
class Tunnel:
    parent: str
    client: str               # busiest client, the host to pull off the network
    clients: int
    queries: int
    unique_subdomains: int
    responses: int
    nxdomain: int
    data_queries: int         # queries of type TXT, NULL or CNAME
    name_len: float           # varying-label characters per query
    entropy: float            # bits per character of the varying labels
    bits_per_query: float
    upload_bytes: int
    first: float
    last: float
    qps: float
    samples: tuple[str, ...]
    cardinality_score: float
    length_score: float
    entropy_score: float
    capacity_score: float
    qtype_score: float
    nxdomain_score: float
    rate_score: float
    sustain_score: float
    volume_score: float
    score: float

    @property
    def duration(self) -> float:
        return self.last - self.first

    def describe(self) -> str:
        return (f"{self.client} -> *.{self.parent}: {self.queries} queries, "
                f"{self.unique_subdomains} unique subdomains, "
                f"~{self.upload_bytes} bytes uploaded "
                f"({self.entropy:.1f} bits/char over {self.name_len:.0f} chars, "
                f"score {self.score:.2f})")


def find_tunnels(events: Iterable[DnsEvent], *, threshold: float = 0.7,
                 min_queries: int = MIN_QUERIES) -> list[Tunnel]:
    """Score every parent domain and return those carrying data, worst first."""
    domains = _group(events)
    window = _capture_window(domains.values())

    found = []
    for parent, domain in domains.items():
        tunnel = score_domain(parent, domain, window, min_queries=min_queries)
        if tunnel is not None and tunnel.score >= threshold:
            found.append(tunnel)
    found.sort(key=lambda t: (t.score, t.upload_bytes), reverse=True)
    return found


@dataclass(frozen=True, slots=True)
class _Query:
    ts: float
    client: str
    name: str
    sub: tuple[str, ...]      # labels below the parent, leftmost first
    qtype: int


@dataclass(slots=True)
class _Domain:
    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    first: float = 0.0
    last: float = 0.0
    records: list[_Query] = field(default_factory=list)


def _group(events: Iterable[DnsEvent]) -> dict[str, _Domain]:
    domains: dict[str, _Domain] = {}
    for event in events:
        parent = event.parent
        # Reverse lookups group into one enormous, entirely benign pseudo
        # domain. They are excluded by structure, not by score.
        if not parent or parent.endswith("arpa"):
            continue
        labels = event.labels
        if len(labels) < 3:
            continue

        domain = domains.get(parent)
        if domain is None:
            if len(domains) >= MAX_DOMAINS:
                continue
            domain = domains[parent] = _Domain(first=event.ts, last=event.ts)

        if event.ts < domain.first:
            domain.first = event.ts
        if event.ts > domain.last:
            domain.last = event.ts

        if event.is_response:
            domain.responses += 1
            if event.rcode == RCODE_NXDOMAIN:
                domain.nxdomain += 1
            continue

        domain.queries += 1
        if len(domain.records) < MAX_RECORDS_PER_DOMAIN:
            domain.records.append(_Query(event.ts, event.client, event.name,
                                         tuple(labels[:-2]), event.qtype))
    return domains


def score_domain(parent: str, domain: _Domain, window: float, *,
                 min_queries: int = MIN_QUERIES) -> Tunnel | None:
    records = domain.records
    if domain.queries < min_queries or len(records) < min_queries:
        return None

    subs = {".".join(record.sub) for record in records}
    if len(subs) < MIN_UNIQUE:
        return None

    constant = _constant_depth(records)
    encoded = [_encoded(record.sub, constant) for record in records]
    lengths = [len(text) for text in encoded]
    name_len = sum(lengths) / len(lengths)
    if name_len <= 0:
        return None

    entropy = sum(_entropy(text) for text in encoded) / len(encoded)
    if entropy < ENTROPY_FLOOR:
        return None

    bits = name_len * entropy
    # Scaled up from the retained sample, which is capped for hostile captures.
    upload_bytes = int(bits / 8 * domain.queries)

    unique_ratio = len(subs) / len(records)
    cardinality_score = _clamp((unique_ratio - UNIQUE_FLOOR) / UNIQUE_SPAN)
    length_score = _clamp((name_len - 15.0) / 45.0)
    entropy_score = _clamp((entropy - ENTROPY_FLOOR) / 1.5)
    capacity_score = _clamp((bits - BITS_FLOOR) / (BITS_CEIL - BITS_FLOOR))

    data_queries = sum(1 for record in records if record.qtype in DATA_QTYPES)
    qtype_score = data_queries / len(records)

    stamps = [record.ts for record in records]
    span = max(stamps) - min(stamps)
    qps = domain.queries / span if span > 0 else float(domain.queries)
    rate_score = _clamp(qps / RATE_CEIL)
    sustain_score = _clamp(span / window) if window > 0 else 0.0
    volume_score = _clamp(upload_bytes / VOLUME_CEIL)

    support = [
        (SUPPORT_QTYPE, qtype_score),
        (SUPPORT_RATE, rate_score),
        (SUPPORT_SUSTAIN, sustain_score),
        (SUPPORT_VOLUME, volume_score),
    ]
    # A capture holding only the query side says nothing about NXDOMAIN, which
    # is not the same as saying every answer succeeded.
    nxdomain_score = domain.nxdomain / domain.responses if domain.responses else 0.0
    if domain.responses:
        support.append((SUPPORT_NXDOMAIN, nxdomain_score))

    weight = sum(w for w, _ in support)
    modulation = sum(w * s for w, s in support) / weight if weight else 0.0
    core = cardinality_score * capacity_score
    score = core * (SUPPORT_FLOOR + (1.0 - SUPPORT_FLOOR) * modulation)

    clients = Counter(record.client for record in records)
    client, _ = clients.most_common(1)[0]

    return Tunnel(
        parent=parent,
        client=client,
        clients=len(clients),
        queries=domain.queries,
        unique_subdomains=len(subs),
        responses=domain.responses,
        nxdomain=domain.nxdomain,
        data_queries=data_queries,
        name_len=name_len,
        entropy=entropy,
        bits_per_query=bits,
        upload_bytes=upload_bytes,
        first=domain.first,
        last=domain.last,
        qps=qps,
        samples=tuple(_samples(records)),
        cardinality_score=cardinality_score,
        length_score=length_score,
        entropy_score=entropy_score,
        capacity_score=capacity_score,
        qtype_score=qtype_score,
        nxdomain_score=nxdomain_score,
        rate_score=rate_score,
        sustain_score=sustain_score,
        volume_score=volume_score,
        score=score,
    )


def _constant_depth(records: Sequence[_Query]) -> int:
    """How many labels above the parent are fixed routing rather than payload.

    Counted from the parent outwards and stopped at the first position that
    varies, so a fixed tunnel prefix and a cloud provider's service labels are
    both removed, while an encoded chunk that happens to repeat once is not.
    """
    depth = 0
    while depth < MAX_CONSTANT_DEPTH:
        values = [record.sub[-1 - depth] for record in records
                  if len(record.sub) > depth + 1]
        if len(values) < len(records) * CONSTANT_SHARE:
            break
        common = Counter(values).most_common(1)[0][1]
        if common < len(records) * CONSTANT_SHARE:
            break
        depth += 1
    return depth


def _encoded(sub: Sequence[str], constant: int) -> str:
    payload = sub[:len(sub) - constant] if constant else sub
    return "".join(payload)[:MAX_ENCODED_CHARS]


def _entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    total = len(text)
    if total < 2:
        return 0.0
    return -sum((count / total) * math.log2(count / total)
                for count in Counter(text).values())


def _samples(records: Sequence[_Query]) -> list[str]:
    """Distinct query names a responder can paste into a search, longest first.

    The longest names are the ones carrying the most data, so they are the ones
    worth showing.
    """
    seen: dict[str, None] = {}
    for record in sorted(records, key=lambda r: len(r.name), reverse=True):
        seen[record.name] = None
        if len(seen) >= SAMPLES:
            break
    return list(seen)


def _capture_window(domains: Iterable[_Domain]) -> float:
    first = last = None
    for domain in domains:
        if first is None or domain.first < first:
            first = domain.first
        if last is None or domain.last > last:
            last = domain.last
    if first is None or last is None:
        return 0.0
    return last - first


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
