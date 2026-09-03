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
                    sits near 5 bits, hex near 4, real hostnames near 3. It is
                    a factor of capacity, never a gate on its own: a floor on
                    it is escaped by encoding in a smaller alphabet
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
  reverse DNS sweeps         .arpa parents are excluded outright, along with
                             every other namespace whose resolution never
                             leaves the local scope (see LOCAL_SCOPE). A tunnel
                             needs an authoritative server the attacker
                             controls, and no name under .arpa, .local or
                             .internal has one; scoring them only produces
                             noise on subnet sweeps, Bonjour chatter and
                             container DNS
  mDNS/Bonjour chatter       instance names under _tcp.local carry device
                             UUIDs and MAC addresses, so they reach tunnel
                             capacity. Excluded by scope: mDNS is answered on
                             the link, never by an attacker's nameserver
  container/cluster DNS      generated pod names under cluster.local are long,
                             unique per pod and near maximal entropy. Same
                             exclusion, since cluster.local is under .local
  DGA traffic                one query per registered domain, so a DGA never
                             reaches MIN_QUERIES under a shared parent. Also
                             tested for DGAs hung off a dynamic DNS parent,
                             where the label is short and low capacity
  antivirus/reputation       MD5 and SHA-1 lookups encoding a hash per query,
                             over TXT, answered NXDOMAIN
  long descriptive names     long but low entropy, and queried repeatedly

Known limitations, all pinned by tests so they cannot regress into silent
claims:

  content addressed names   any service that names a host after a hash or a
                            long random identifier is not separable from a
                            tunnel by content: SHA-256 reputation lookups and
                            IPFS subdomain gateways both put ~250 bits of
                            near-maximal-entropy data in a label sent to a
                            fixed parent. Separating those needs a domain
                            allowlist, which is deployment data and
                            deliberately not baked in here
  low capacity chunking     a tunnel that keeps under BITS_FLOOR per query
                            evades the capacity gate, at roughly 11 bytes a
                            query. That region also contains every CDN, GUID
                            and session hostname on the internet, so it cannot
                            be reclaimed by lowering the gate
  duplicate padding         cardinality is a ratio, so re-asking each encoded
                            name a few times dilutes it. It cannot dilute it
                            to nothing: novelty measures the distinct data a
                            parent has carried, which padding cannot reduce
  public suffixes           grouping is on the last two labels, so a tunnel
                            under example.co.uk merges with its neighbours.
                            No public suffix list is bundled; that is data
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

# Namespaces whose resolution never leaves the local scope, so no attacker
# controlled nameserver can be on the other end of a query and no exfiltration
# channel exists however encoded the names look. Excluded structurally rather
# than by score: .arpa carries reverse sweeps, .local carries mDNS/Bonjour
# instance names and Kubernetes cluster.local, .internal carries cloud and
# container hostnames. Reserved-but-ordinarily-resolved names (.test,
# .example) are deliberately not here, since a resolver treats them like any
# other name.
LOCAL_SCOPE = frozenset({"arpa", "local", "localhost", "internal", "invalid",
                         "onion", "alt"})

# Bits per query below which the name cannot be carrying meaningful payload,
# and above which it is carrying as much as a tunnel bothers to send. This is
# the gate: below the floor the domain is not scored at all, because capacity
# is the one thing a tunnel cannot trade away.
BITS_FLOOR = 90.0
BITS_CEIL = 240.0
# Per-character entropy of an ordinary hostname, the reference the reported
# entropy_score is measured against. Entropy is deliberately not a gate of its
# own: gating on it rejects any low-alphabet encoding outright, so a tunnel
# escapes the detector entirely by encoding in base 8 rather than base 32. What
# matters is what a name can carry, and capacity already prices the alphabet.
ENTROPY_BASE = 3.3

# Distinct subdomains per query. Benign clients revisit names; a tunnel cannot.
UNIQUE_FLOOR = 0.40
UNIQUE_SPAN = 0.50
# Revisiting only exculpates a parent that has few distinct names to revisit.
# Once it has served this many bytes of distinct encoded content, re-asking
# those names says nothing, so padding a tunnel with duplicate queries cannot
# dilute cardinality to zero.
NOVEL_CEIL = 4096.0

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
        # Locally scoped namespaces have no attacker-reachable authority, so
        # they are excluded by structure rather than by score.
        if not parent or parent.rsplit(".", 1)[-1] in LOCAL_SCOPE:
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
    bits = name_len * entropy
    if bits < BITS_FLOOR:
        return None

    # A repeated name carries no new data, so the estimate counts distinct ones
    # and scales that back up from the retained sample, which is capped for
    # hostile captures.
    novel = len(subs) * domain.queries / len(records)
    upload_bytes = int(bits / 8 * novel)

    unique_ratio = len(subs) / len(records)
    novelty_score = _clamp(len(subs) * bits / 8 / NOVEL_CEIL)
    cardinality_score = max(_clamp((unique_ratio - UNIQUE_FLOOR) / UNIQUE_SPAN),
                            novelty_score)
    length_score = _clamp((name_len - 15.0) / 45.0)
    entropy_score = _clamp((entropy - ENTROPY_BASE) / 1.5)
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
