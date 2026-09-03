# pcapinator

Network threat hunting for packet captures. Reads a pcap or pcapng file and
reports command-and-control beaconing, DNS tunneling, algorithmically generated
domains, and network scans, with the statistics behind every finding.

**No third-party dependencies.** The capture readers and every protocol decoder
(Ethernet, VLAN, Linux SLL, IPv4, IPv6 with extension headers, TCP, UDP, ICMP,
DNS) are written from the format specifications using `struct`. Python 3.10+
standard library only.

## Measured results

Detectors are scored against generated traffic with known ground truth,
including benign traffic deliberately shaped to resemble each threat. Reproduce
with `python tools/evaluate.py`.

| Detector | Detected | Missed | False positives | Benign but periodic |
|---|---|---|---|---|
| beacon | 5/5 | 0 | 0 | 2 |
| dga | 1/1 | 0 | 0 | 0 |
| scan | 2/2 | 0 | 0 | 0 |
| tunnel | 1/1 | 0 | 0 | 0 |
| **total** | **9/9** | **0** | **0** | **2** |

100% detection across 9 planted threats and 13 scenarios, 0 false positives.

The two benign-but-periodic results are a health-check monitor and a reverse-DNS
sweep. Both are scripted, so both really are on a schedule. See
[Limitations](#limitations); they are reported rather than suppressed, on
purpose.

## Quick start

```bash
python -m venv .venv
./.venv/bin/pip install -e ".[dev]"

# generate a labelled capture containing every threat plus its benign twin
./.venv/bin/pcapinator --demo demo.pcap

# analyse your own
./.venv/bin/pcapinator capture.pcapng
./.venv/bin/pcapinator capture.pcap.gz --only beacon,tunnel --threshold 0.8
./.venv/bin/pcapinator capture.pcap --json
```

Exit status is `0` for no findings, `1` when findings are reported, `2` on
error, so it drops into a pipeline.

```
pcapinator demo.pcap
  4,999 packets, 4,999 decoded, 1,243 flows, 1,014 DNS queries, 43.3m of traffic

  critical 2  high 3  medium 5

  [CRITICAL] Scheduled callbacks 10.0.0.5 -> 203.0.113.9:443
        score 0.92, destination external
        period                 57.0s +/- 3.9s
        connections            45
        missed check-ins       0
        interval regularity    0.93
        payload consistency    1.00
        capture coverage       1.00

  [CRITICAL] Half Open scan 10.0.0.77 -> 200 hosts:445
        score 1.00
        attempts               200
        distinct hosts         200
        rate                   250.0/s
        bare SYNs              98%
        unserved share         100%

  [MEDIUM] DNS tunnel 10.0.0.31 -> exfil.example
        score 0.78
        queries                300
        unique subdomains      300
        mean name length       48 bytes
        label entropy          4.44 bits/char
        estimated upload       7,998 bytes
        sample                 dffxktqnck3zx4rcbx5uy3kl.poblulixl42xwx4kz5p7r7w5.t.exfil.example
```

Every finding shows the statistics that produced it. A tool that says
"suspicious, 0.86" cannot be checked or argued with; one that shows the interval,
the jitter, and the sample count can be.

## What it detects

### C2 beaconing

Implants call home on a schedule. Matching identical intervals finds none of
them, because every real framework jitters its callbacks and any implant on a
laptop misses check-ins while the host sleeps. Four independent signals are
combined instead:

- **interval regularity**, by median absolute deviation, which unlike standard
  deviation is not dragged around by a single outage
- **interval symmetry**, by Bowley skewness; scheduled traffic is symmetric about
  its period, human-driven traffic is heavily right-skewed
- **payload consistency**; check-ins carry near-identical amounts of data
- **schedule coverage**, separating a beacon from a brief burst that happened to
  look regular

Missed check-ins are folded onto the estimated base period, so a 180s gap in a
60s schedule is evidence *for* the schedule. Folding is constrained, because
given a free choice of multiple per gap any interval set folds onto some small
period, which is the submultiple degeneracy familiar from pitch detection. Two
constraints remove it: a gap counts as missed check-ins only if it lands within
35% of an exact multiple, and among candidates that fit equally well the largest
period wins, since every submultiple of a true period fits whatever the period
does.

Detected across 0%, 15%, and 30% jitter, hourly periods, and schedules where a
third of callbacks are skipped.

### DNS tunneling

Grouped by parent domain, scored on subdomain cardinality, query-name length,
Shannon entropy of the leftmost labels, query-type skew toward TXT and NULL,
NXDOMAIN ratio, sustained rate, and estimated bytes encoded in query names.

Tested against CDN domains with large subdomain cardinality and against
`in-addr.arpa` sweeps, both of which are high-cardinality and benign.

### Algorithmic domains

Character bigram log-probability against a model built from the system word list,
plus entropy, length, vowel ratio, longest consonant run, and digit ratio.
`tools/build_bigrams.py` regenerates the committed table.

Findings are grouped per host, not per domain: a DGA produces domains by the
hundred and an implant walks the list until one resolves, so one infected host
is one finding however many names it tried.

### Scans

Vertical port sweeps, horizontal host sweeps, and half-open SYN scans, from
fan-out, unserved share, timing uniformity, and payload volume.

The discriminating case is that ordinary browsing looks exactly like a
horizontal sweep: one host, many destinations, one port. What separates them is
whether the connections were served.

## How it works

```
pcap.py        libpcap and pcapng readers, both byte orders, nanosecond
               timestamps, multi-interface sections, transparent gzip
layers/        link.py   Ethernet, VLAN and QinQ stacks, Linux SLL/SLL2, raw IP
               inet.py   IPv4, IPv6 extension header walking, TCP, UDP, ICMP
               dns.py    DNS wire format including compression pointers
               types.py  the Frame and Flow contracts every detector consumes
flows.py       bidirectional flow assembly, memory-bounded by idle expiry
dnsview.py     DNS activity lifted out of the frame stream
detect/        beacon.py  scan.py  dnstunnel.py  dga.py
report.py      normalised findings, terminal and JSON rendering
synth.py       labelled traffic generation with known ground truth
```

One pass over the capture feeds everything. Packets are decoded once, flows
assemble as frames stream past, and DNS is lifted from the same frames, so a
multi-gigabyte capture is never buffered or read twice.

## Design decisions

**Captures are untrusted input.** A threat hunting tool ingests
attacker-influenced data by definition. Every length field is bounded before it
is used to allocate. Testing found a real denial of service during development:
a single legal 65,507-byte DNS message shaped as one acyclic compression-pointer
chain took 9.8 seconds to parse, because a visited-offset guard proves
termination without bounding work. A per-name jump cap fixed it.

**Periodicity is not maliciousness.** A monitor polling a service every ten
seconds scores higher than most real implants, because it is a more perfect
beacon. No timing statistic separates them. The score therefore means one thing
only, how strongly traffic is scheduled, and ranking moves to the reporting
layer, which has context timing lacks. Destination scope is the first piece of
that context.

**Internal destinations are never suppressed.** Suppressing them would hide
lateral movement, which is exactly what you want to catch.

**Classification uses the real internal ranges.** Python's
`ipaddress.is_private` returns `True` for the RFC 5737 documentation ranges. Those
stand in for public address space, so a tool that leans on it mislabels them as
internal. RFC 1918, RFC 6598 and RFC 4193 are matched explicitly.

## Limitations

Stated because a detector without known limits has not been tested properly.

- **Scripted benign traffic is indistinguishable from beaconing.** Monitoring
  checks, backup jobs, NTP, and update pollers are periodic by construction.
  This is not solvable with better statistics and is handled with context and
  analyst review, not suppression.
- **A beacon slower than the capture leaves nothing to measure.** A daily
  callback needs days of traffic.
- **Dictionary-word DGAs are not detected.** Families that chain real words
  produce pronounceable names a bigram model scores as ordinary.
- **Very short domains carry too little signal** to score reliably.
- **Reputation-lookup services that encode hashes into subdomains** genuinely
  resemble DNS tunneling and are not separated.
- **Encrypted DNS bypasses the DNS detectors entirely.** DoH is HTTPS.
- **A patient attacker evades the timing detectors** by beaconing slower than
  the capture window or randomising far beyond normal jitter, at the cost of
  responsiveness.

## Development

```bash
./.venv/bin/python -m pytest          # 475 tests
./.venv/bin/python tools/evaluate.py  # detection and false positive rates
```

Tests are built from hand-assembled bytes constructed field by field from the
protocol specifications, so a passing test means agreement with the spec rather
than with the implementation. Malformed and hostile inputs are explicit cases.

## License

MIT
