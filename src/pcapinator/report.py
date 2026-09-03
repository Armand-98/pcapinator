"""Findings rendering.

Detectors return rich, detector-specific results. This normalises them to one
shape so a capture produces a single ranked list, and so adding a detector does
not mean touching the output code.

Every finding carries the statistics that produced it. A tool that says
"suspicious, score 0.86" and stops cannot be checked, argued with, or learned
from; one that shows the interval, the jitter and the sample count can be. The
analyst, not the tool, decides what is malicious.
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .detect.beacon import scope as beacon_scope

CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

_COLOURS = {CRITICAL: "\033[1;31m", HIGH: "\033[31m",
            MEDIUM: "\033[33m", LOW: "\033[36m"}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    title: str
    score: float
    severity: str
    src: str = ""
    dst: str = ""
    scope: str = ""
    evidence: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "title": self.title,
            "score": round(self.score, 4),
            "severity": self.severity,
            "src": self.src,
            "dst": self.dst,
            "scope": self.scope,
            "evidence": dict(self.evidence),
        }


@dataclass(slots=True)
class Summary:
    capture: str
    packets: int = 0
    decoded: int = 0
    flows: int = 0
    dns_queries: int = 0
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)

    def ranked(self) -> list[Finding]:
        return sorted(self.findings,
                      key=lambda f: (_ORDER[f.severity], -f.score))

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def severity_for(score: float, scope: str = "") -> str:
    """Grade a finding, using destination scope where the score alone cannot.

    Confidence and severity are not the same thing. A perfectly scheduled
    conversation to a host on the local subnet is a confident finding and a
    routine one; the same schedule leaving the network is worth waking someone
    for. Scope is the cheapest context that separates them, so an external
    destination lifts a finding one grade and never lowers one.
    """
    external = scope in ("external", "unknown", "")
    if score >= 0.9:
        return CRITICAL if external else HIGH
    if score >= 0.8:
        return HIGH if external else MEDIUM
    if score >= 0.7:
        return MEDIUM
    return LOW


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_json(summary: Summary) -> str:
    return json.dumps({
        "capture": summary.capture,
        "packets": summary.packets,
        "decoded": summary.decoded,
        "flows": summary.flows,
        "dns_queries": summary.dns_queries,
        "capture_duration_seconds": round(summary.duration, 3),
        "counts": summary.counts(),
        "findings": [finding.as_dict() for finding in summary.ranked()],
    }, indent=2)


def render_text(summary: Summary, *, colour: bool | None = None,
                width: int = 78) -> str:
    colour = use_colour() if colour is None else colour
    paint = _painter(colour)
    lines: list[str] = []

    lines.append(paint(f"pcapinator {summary.capture}", _BOLD))
    lines.append(paint(
        f"  {summary.packets:,} packets, {summary.decoded:,} decoded, "
        f"{summary.flows:,} flows, {summary.dns_queries:,} DNS queries, "
        f"{_duration(summary.duration)} of traffic", _DIM))
    lines.append("")

    findings = summary.ranked()
    if not findings:
        lines.append("  No findings.")
        lines.append(paint(
            "  Absence of a finding is not absence of a threat: a beacon slower "
            "than the capture, or one that never repeats within it, leaves "
            "nothing to measure.", _DIM))
        return "\n".join(lines) + "\n"

    counts = summary.counts()
    tally = "  ".join(f"{paint(name, _COLOURS[name])} {counts[name]}"
                      for name in (CRITICAL, HIGH, MEDIUM, LOW) if name in counts)
    lines.append(f"  {tally}")
    lines.append("")

    for finding in findings:
        tag = paint(f"[{finding.severity.upper()}]", _COLOURS[finding.severity])
        lines.append(f"  {tag} {paint(finding.title, _BOLD)}")
        detail = f"score {finding.score:.2f}"
        if finding.scope:
            detail += f", destination {finding.scope}"
        lines.append(paint(f"        {detail}", _DIM))
        for label, value in finding.evidence:
            lines.append(f"        {label:<22} {value}")
        lines.append("")

    return "\n".join(lines)


def collect(*groups: Iterable[Finding]) -> list[Finding]:
    return [finding for group in groups for finding in group]


def _painter(colour: bool):
    if not colour:
        return lambda text, _code="": text
    return lambda text, code="": f"{code}{text}{_RESET}" if code else text


def _duration(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def evidence(*pairs: tuple[str, object]) -> tuple[tuple[str, str], ...]:
    return tuple((label, str(value)) for label, value in pairs)


def beacon_findings(beacons: Sequence) -> list[Finding]:
    return [
        Finding(
            kind="beacon",
            title=f"Scheduled callbacks {b.src} -> {b.dst}:{b.dport}",
            score=b.score,
            severity=severity_for(b.score, b.dst_scope),
            src=b.src, dst=b.dst, scope=b.dst_scope,
            evidence=evidence(
                ("period", f"{b.period:.1f}s +/- {b.jitter:.1f}s"),
                ("connections", b.connections),
                ("missed check-ins", b.missed),
                ("bytes sent", f"{b.bytes_out:,}"),
                ("interval regularity", f"{b.interval_score:.2f}"),
                ("payload consistency", f"{b.size_score:.2f}"),
                ("capture coverage", f"{b.coverage_score:.2f}"),
            ),
        )
        for b in beacons
    ]


def scan_findings(scans: Sequence) -> list[Finding]:
    findings = []
    for s in scans:
        target = f"{s.dst}" if s.dst else f"{s.hosts} hosts"
        port = f":{s.dport}" if s.dport else ""
        findings.append(Finding(
            kind="scan",
            title=f"{s.kind.replace('_', ' ').title()} scan {s.src} -> {target}{port}",
            score=s.score,
            severity=severity_for(s.score, beacon_scope(s.dst) if s.dst else ""),
            src=s.src, dst=s.dst or "", scope=beacon_scope(s.dst) if s.dst else "",
            evidence=evidence(
                ("attempts", f"{s.attempts:,}"),
                ("distinct hosts", s.hosts),
                ("distinct ports", s.ports),
                ("rate", f"{s.rate:.1f}/s"),
                ("bare SYNs", f"{s.half_open_ratio:.0%}"),
                ("unserved share", f"{s.response_score:.0%}"),
                ("fan-out signal", f"{s.fanout_score:.2f}"),
                ("timing signal", f"{s.timing_score:.2f}"),
            ),
        ))
    return findings


def tunnel_findings(tunnels: Sequence) -> list[Finding]:
    return [
        Finding(
            kind="tunnel",
            title=f"DNS tunnel {t.client} -> {t.parent}",
            score=t.score,
            severity=severity_for(t.score),
            src=t.client, dst=t.parent,
            evidence=evidence(
                ("queries", f"{t.queries:,}"),
                ("unique subdomains", f"{t.unique_subdomains:,}"),
                ("mean name length", f"{t.name_len:.0f} bytes"),
                ("label entropy", f"{t.entropy:.2f} bits/char"),
                ("estimated upload", f"{t.upload_bytes:,} bytes"),
                ("NXDOMAIN", f"{t.nxdomain}/{t.responses}"),
                ("query rate", f"{t.qps:.2f}/s"),
                ("sample", t.samples[0] if t.samples else ""),
            ),
        )
        for t in tunnels
    ]


def dga_findings(scores: Sequence, clients: dict[str, str] | None = None) -> list[Finding]:
    """One finding per host, not per domain.

    A domain generation algorithm produces domains by the hundred, and an
    implant walks the list until one resolves. Reporting each name separately
    buries every other detector under algorithmic noise and misrepresents the
    incident: one infected host is one finding, however many domains it tried.
    """
    clients = clients or {}
    grouped: dict[str, list] = defaultdict(list)
    for score in scores:
        grouped[clients.get(score.domain, "")].append(score)

    findings = []
    for client, hits in grouped.items():
        hits.sort(key=lambda hit: hit.score, reverse=True)
        best = hits[0]
        mean = sum(hit.score for hit in hits) / len(hits)
        where = f" from {client}" if client else ""
        title = (f"Algorithmic domain lookups{where}" if len(hits) > 1
                 else f"Algorithmic domain {best.domain}{where}")
        findings.append(Finding(
            kind="dga",
            title=title,
            score=best.score,
            severity=severity_for(best.score),
            src=client, dst=best.domain,
            evidence=evidence(
                ("domains", len(hits)),
                ("highest score", f"{best.score:.2f}"),
                ("mean score", f"{mean:.2f}"),
                ("examples", ", ".join(hit.domain for hit in hits[:4])),
                ("bigram log-prob", f"{best.bigram:.2f}"),
                ("entropy", f"{best.entropy:.2f} bits/char"),
                ("longest consonant run", best.consonant_run),
            ),
        ))
    findings.sort(key=lambda finding: finding.score, reverse=True)
    return findings
