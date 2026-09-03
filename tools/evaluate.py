#!/usr/bin/env python3
"""Measure detection rate and false positive rate against known ground truth.

A detector's worth is a number, not an adjective. Every scenario here is
generated with a known answer, including benign traffic deliberately shaped like
each threat, so both halves can be measured: what is caught, and what is
wrongly accused.

Run from the repo root:
    ./.venv/bin/python tools/evaluate.py
    ./.venv/bin/python tools/evaluate.py --markdown     # table for the README
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pcapinator.cli import analyse                       # noqa: E402
from pcapinator.synth import (Scenario, Truth, beacon, browsing,  # noqa: E402
                              cdn_lookups, dga_lookups, dns_tunnel,
                              health_checks, horizontal_scan, merge,
                              reverse_sweep, vertical_scan)

CLIENT, C2, RESOLVER = "10.0.0.5", "203.0.113.9", "10.0.0.1"


def scenarios() -> list[Scenario]:
    """Threats to catch, and benign traffic shaped like them."""
    return [
        # --- threats ---
        beacon(CLIENT, C2, 443, period=60.0, count=45),
        _named("beacon_jitter15",
               beacon(CLIENT, C2, 443, period=60.0, count=45, jitter=0.15, seed=11)),
        _named("beacon_jitter30",
               beacon(CLIENT, C2, 443, period=60.0, count=45, jitter=0.30, seed=12)),
        _named("beacon_hourly",
               beacon(CLIENT, C2, 8443, period=3600.0, count=24, jitter=0.05, seed=13)),
        _named("beacon_missed", _missed_checkins()),
        vertical_scan("10.0.0.77", "10.0.0.20"),
        horizontal_scan("10.0.0.77", "10.0.0", 445),
        dns_tunnel("10.0.0.31", RESOLVER, "exfil.example"),
        dga_lookups("10.0.0.42", RESOLVER),

        # --- benign, shaped like the above ---
        browsing("10.0.0.12"),
        cdn_lookups("10.0.0.12", RESOLVER),
        reverse_sweep("10.0.0.8", RESOLVER),
        health_checks("10.0.0.9", "10.0.0.20", 8080),
    ]


def _named(name: str, scenario: Scenario) -> Scenario:
    scenario.name = name
    return scenario


def _missed_checkins() -> Scenario:
    """A beacon on a laptop that sleeps: every third callback is skipped."""
    import random
    rng = random.Random(17)
    frames, now = [], 1000.0
    from pcapinator.synth import tcp_session
    for index in range(45):
        frames += tcp_session(now, CLIENT, C2, 40000 + index, 443, 512,
                              response_size=64)
        now += 60.0 * (1 + (rng.choice([1, 2]) if rng.random() < 0.3 else 0))
    return Scenario("beacon_missed", frames,
                    [Truth("beacon", CLIENT, C2, 443, "60s with skips")])


def matches(finding, truth: Truth) -> bool:
    if finding.kind != truth.kind:
        return False
    if truth.src and finding.src != truth.src:
        return False
    if truth.dst and truth.dst not in (finding.dst or ""):
        return False
    return True


@dataclass
class Result:
    scenario: str
    expected: list[Truth]
    found: list = field(default_factory=list)
    tolerated: tuple[str, ...] = ()

    @property
    def hits(self) -> list[Truth]:
        return [t for t in self.expected if any(matches(f, t) for f in self.found)]

    @property
    def missed(self) -> list[Truth]:
        return [t for t in self.expected if not any(matches(f, t) for f in self.found)]

    @property
    def _unmatched(self) -> list:
        return [f for f in self.found
                if not any(matches(f, t) for t in self.expected)]

    @property
    def spurious(self) -> list:
        """Findings that are wrong."""
        return [f for f in self._unmatched if f.kind not in self.tolerated]

    @property
    def benign_periodic(self) -> list:
        """Findings that are correct about the traffic and not about a threat.

        Scripted benign activity really is periodic. Counting these as errors
        would misstate the detector; hiding them would misstate the tool.
        """
        return [f for f in self._unmatched if f.kind in self.tolerated]


def evaluate(threshold: float) -> list[Result]:
    results = []
    with tempfile.TemporaryDirectory() as workdir:
        for scenario in scenarios():
            path = scenario.write(Path(workdir) / f"{scenario.name}.pcap")
            summary = analyse(path, threshold=threshold)
            results.append(Result(scenario.name, scenario.truth,
                                  summary.findings, scenario.tolerated))
    return results


def totals(results: list[Result]) -> dict[str, dict[str, int]]:
    per_kind: dict[str, dict[str, int]] = {}

    def bucket(kind: str) -> dict[str, int]:
        return per_kind.setdefault(kind, {"tp": 0, "fn": 0, "fp": 0, "benign": 0})

    for result in results:
        for truth in result.expected:
            bucket(truth.kind)["tp" if truth in result.hits else "fn"] += 1
        for finding in result.spurious:
            bucket(finding.kind)["fp"] += 1
        for finding in result.benign_periodic:
            bucket(finding.kind)["benign"] += 1
    return per_kind


def render(results: list[Result], per_kind, threshold: float, markdown: bool) -> str:
    lines = []
    tp = sum(k["tp"] for k in per_kind.values())
    fn = sum(k["fn"] for k in per_kind.values())
    fp = sum(k["fp"] for k in per_kind.values())
    benign = sum(k["benign"] for k in per_kind.values())
    recall = tp / (tp + fn) if tp + fn else 0.0

    if markdown:
        lines.append(f"Measured at threshold {threshold}, "
                     f"{len(results)} scenarios, seeds fixed.\n")
        lines.append("| Detector | Detected | Missed | False positives | Benign but periodic |")
        lines.append("|---|---|---|---|---|")
        for kind in sorted(per_kind):
            k = per_kind[kind]
            lines.append(f"| {kind} | {k['tp']}/{k['tp'] + k['fn']} | "
                         f"{k['fn']} | {k['fp']} | {k['benign']} |")
        lines.append(f"| **total** | **{tp}/{tp + fn}** | **{fn}** | **{fp}** | **{benign}** |")
        lines.append(f"\nDetection rate {recall:.0%} across {tp + fn} planted "
                     f"threats and {len(results)} scenarios, with {fp} false "
                     f"positives.")
        if benign:
            lines.append(f"\nThe {benign} benign-but-periodic result(s) are scripted "
                         f"activity that really is on a schedule. No timing statistic "
                         f"separates them from an implant; they are reported with their "
                         f"destination scope so an analyst can dismiss them, not "
                         f"suppressed.")
    else:
        lines.append(f"pcapinator evaluation, threshold {threshold}")
        lines.append("=" * 64)
        for result in results:
            status = "ok" if not result.missed and not result.spurious else "!!"
            lines.append(f"{status} {result.scenario:<20} "
                         f"expected {len(result.expected)}, "
                         f"found {len(result.found)}, "
                         f"missed {len(result.missed)}, "
                         f"spurious {len(result.spurious)}")
            for truth in result.missed:
                lines.append(f"     MISS  {truth.kind} {truth.src} -> {truth.dst}")
            for finding in result.spurious:
                lines.append(f"     FP    {finding.kind} {finding.title} "
                             f"({finding.score:.2f})")
            for finding in result.benign_periodic:
                lines.append(f"     NOTE  benign but genuinely periodic: "
                             f"{finding.title} ({finding.score:.2f})")
        lines.append("=" * 64)
        for kind in sorted(per_kind):
            k = per_kind[kind]
            total = k["tp"] + k["fn"]
            lines.append(f"  {kind:<8} detected {k['tp']}/{total}  "
                         f"false positives {k['fp']}  "
                         f"benign-periodic {k['benign']}")
        lines.append(f"  {'TOTAL':<8} detected {tp}/{tp + fn} ({recall:.0%})  "
                     f"false positives {fp}  benign-periodic {benign}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.7)
    parser.add_argument("--markdown", action="store_true",
                        help="emit the README table")
    args = parser.parse_args()

    results = evaluate(args.threshold)
    per_kind = totals(results)
    print(render(results, per_kind, args.threshold, args.markdown))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
