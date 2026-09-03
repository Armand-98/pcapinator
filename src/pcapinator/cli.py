"""Command line entry point.

One pass over the capture feeds everything. Packets are decoded once, flows are
assembled as the frames stream past, and DNS is lifted out of the same frames,
so a multi-gigabyte capture never has to be held in memory or read twice.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from .detect.beacon import find_beacons, is_local
from .detect.dga import find_dga
from .detect.dnstunnel import find_tunnels
from .detect.scan import find_scans
from .dnsview import dns_event
from .flows import assemble
from .menu import TUTORIAL, ask, clean_path, interactive
from .menu import run as run_menu
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
            only: tuple[str, ...] = DETECTORS, strict: bool = False,
            local_nets: tuple = ()) -> Summary:
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
        beacons = find_beacons(flows, threshold=threshold, local_nets=local_nets)
        if local_nets:
            # Beaconing means a host inside the network calling out. Without a
            # declared network there is no way to tell which side is which, so
            # every schedule is reported; once the analyst says which addresses
            # are theirs, an inbound schedule is someone else's probe. Pointed
            # at an internet facing server this is the difference between four
            # findings and a hundred and sixty five.
            beacons = [b for b in beacons if is_local(b.src, local_nets)]
        summary.findings += beacon_findings(beacons)
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


def _menu_action(_number: int, entry) -> int | None:
    """Run one menu choice. Returning None sends the user back to the menu."""
    name, _blurb, only = entry

    if name == "Tutorial":
        print(TUTORIAL)
        return None

    if name == "Demo":
        target = ask("Write the demo capture to", "demo.pcap")
        if not target:
            return None
        path = demo_capture(Path(clean_path(target)))
        print(f"   wrote {path}")
    else:
        answer = ask("Capture file")
        if not answer:
            return None
        path = Path(clean_path(answer))
        if not path.is_file():
            print(f"   no such file: {path}")
            return None

    try:
        summary = analyse(path, only=only or DETECTORS)
    except CaptureError as error:
        print(f"   {path}: {error}")
        return None
    except OSError as error:
        print(f"   {error}")
        return None

    print()
    print(render_text(summary))
    return None


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
    parser.add_argument("--local-net", metavar="CIDR", action="append", default=[],
                        help="network you own, repeatable. Restricts beaconing to "
                             "hosts calling out from inside it, and decides which "
                             "destinations count as external. Defaults to the "
                             "RFC 1918 and RFC 6598 ranges")
    parser.add_argument("--top", type=int, metavar="N",
                        help="show only the N highest ranked findings")
    parser.add_argument("--no-color", action="store_true",
                        help="never colourise output")
    parser.add_argument("--demo", metavar="FILE",
                        help="write a labelled demo capture to FILE and analyse it")
    parser.add_argument("--version", action="version",
                        version=f"pcapinator {VERSION}")
    args = parser.parse_args(argv)

    if not args.capture and not args.demo:
        # A terminal gets the menu. A pipe or a script gets the error, because
        # a prompt nobody is there to answer is worse than a clear failure.
        if interactive() and argv is None:
            return run_menu("pcapinator", _menu_action)
        parser.error("give a capture file, or --demo FILE to generate one")
    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0 and 1")
    if args.top is not None and args.top < 1:
        parser.error("--top must be at least 1")

    local_nets = []
    for cidr in args.local_net:
        try:
            local_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as error:
            parser.error(f"--local-net {cidr}: {error}")

    only = DETECTORS
    if args.only:
        only = tuple(name.strip().lower() for name in args.only.split(",") if name.strip())
        unknown = [name for name in only if name not in DETECTORS]
        if unknown:
            parser.error(f"unknown detector(s): {', '.join(unknown)}")

    path = Path(args.capture) if args.capture else demo_capture(Path(args.demo))

    try:
        summary = analyse(path, threshold=args.threshold, only=only,
                          strict=args.strict, local_nets=tuple(local_nets))
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
        print(render_text(summary, colour=colour, limit=args.top), end="")

    return EXIT_FINDINGS if summary.findings else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
