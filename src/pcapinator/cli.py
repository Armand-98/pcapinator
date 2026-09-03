"""Command line entry point.

One pass over the capture feeds everything. Packets are decoded once, flows are
assembled as the frames stream past, and DNS is lifted out of the same frames,
so a multi-gigabyte capture never has to be held in memory or read twice.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detect.beacon import find_beacons
from .detect.dga import find_dga
from .detect.dnstunnel import find_tunnels
from .detect.scan import find_scans
from .dnsview import dns_event
from .flows import assemble
from .layers import decode
from .pcap import CaptureError, read_packets
from .report import (Summary, beacon_findings, dga_findings, render_json,
                     render_text, scan_findings, tunnel_findings)

VERSION = "0.1.0"
DETECTORS = ("beacon", "scan", "tunnel", "dga")

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def analyse(path: str | Path, *, threshold: float = 0.7,
            only: tuple[str, ...] = DETECTORS, strict: bool = False) -> Summary:
    summary = Summary(capture=str(path))
    events: list = []
    span: list[float] = []

    def frames():
        """Decode once, and tee DNS out on the way past.

        Side-effecting deliberately: flow assembly and DNS extraction both need
        every frame, and a capture is too large to buffer or to read twice.
        """
        for packet in read_packets(path, strict=strict):
            summary.packets += 1
            frame = decode(packet)
            if frame is None:
                continue
            summary.decoded += 1
            span.append(frame.ts)
            event = dns_event(frame)
            if event is not None:
                events.append(event)
            yield frame

    flows = list(assemble(frames()))
    summary.flows = len(flows)
    summary.dns_queries = sum(1 for event in events if not event.is_response)
    if span:
        summary.duration = max(span) - min(span)

    if "beacon" in only:
        summary.findings += beacon_findings(find_beacons(flows, threshold=threshold))
    if "scan" in only:
        summary.findings += scan_findings(find_scans(flows, threshold=threshold))
    if "tunnel" in only:
        summary.findings += tunnel_findings(find_tunnels(events, threshold=threshold))
    if "dga" in only:
        summary.findings += dga_findings(find_dga(events, threshold=threshold),
                                         _clients(events))
    return summary


def _clients(events) -> dict[str, str]:
    """Which host asked for a domain, so a DGA hit names a machine to go look at."""
    clients: dict[str, str] = {}
    for event in events:
        if not event.is_response:
            clients.setdefault(event.name, event.client)
            clients.setdefault(event.parent, event.client)
    return clients


def demo_capture(path: Path) -> Path:
    """Write a labelled capture containing every threat and its benign twin."""
    from .synth import (beacon, browsing, cdn_lookups, dga_lookups, dns_tunnel,
                        health_checks, horizontal_scan, merge, reverse_sweep,
                        vertical_scan)

    return merge(
        "demo",
        beacon("10.0.0.5", "203.0.113.9", 443, period=60.0, count=45, jitter=0.15),
        vertical_scan("10.0.0.77", "10.0.0.20"),
        horizontal_scan("10.0.0.77", "10.0.0", 445),
        dns_tunnel("10.0.0.31", "10.0.0.1", "exfil.example"),
        dga_lookups("10.0.0.42", "10.0.0.1"),
        browsing("10.0.0.12"),
        cdn_lookups("10.0.0.12", "10.0.0.1"),
        reverse_sweep("10.0.0.8", "10.0.0.1"),
        health_checks("10.0.0.9", "10.0.0.20", 8080),
    ).write(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pcapinator",
        description="Hunt a packet capture for C2 beaconing, DNS tunneling, "
                    "algorithmic domains and network scans.",
        epilog="Exit status: 0 no findings, 1 findings reported, 2 error.")
    parser.add_argument("capture", nargs="?",
                        help="pcap or pcapng file, optionally gzipped")
    parser.add_argument("--json", action="store_true",
                        help="machine readable output")
    parser.add_argument("--only", metavar="LIST",
                        help=f"comma separated subset of {','.join(DETECTORS)}")
    parser.add_argument("--threshold", type=float, default=0.7, metavar="N",
                        help="minimum score to report, 0 to 1 (default 0.7)")
    parser.add_argument("--strict", action="store_true",
                        help="fail on a truncated capture instead of reading "
                             "what is there")
    parser.add_argument("--no-color", action="store_true",
                        help="never colourise output")
    parser.add_argument("--demo", metavar="FILE",
                        help="write a labelled demo capture to FILE and analyse it")
    parser.add_argument("--version", action="version",
                        version=f"pcapinator {VERSION}")
    args = parser.parse_args(argv)

    if not args.capture and not args.demo:
        parser.error("give a capture file, or --demo FILE to generate one")
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")

    only = DETECTORS
    if args.only:
        only = tuple(name.strip().lower() for name in args.only.split(",") if name.strip())
        unknown = [name for name in only if name not in DETECTORS]
        if unknown:
            parser.error(f"unknown detector(s): {', '.join(unknown)}")

    path = Path(args.capture) if args.capture else demo_capture(Path(args.demo))

    try:
        summary = analyse(path, threshold=args.threshold, only=only,
                          strict=args.strict)
    except CaptureError as error:
        print(f"pcapinator: {path}: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        print(f"pcapinator: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(render_json(summary))
    else:
        colour = False if args.no_color else None
        print(render_text(summary, colour=colour), end="")

    return EXIT_FINDINGS if summary.findings else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
