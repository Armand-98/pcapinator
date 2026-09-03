"""Interactive menu shown when the tool is run with no arguments.

The flags are the real interface and everything here routes to them. The menu
exists so the tool is usable without first reading the help, which is how it
gets picked up by someone who has a capture and a question rather than a
workflow.

Nothing here runs unless stdin is a terminal, so piping into the tool or running
it from a script still fails fast on a missing argument instead of hanging on a
prompt that nobody will ever answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

BRAND = "LyfieldCreationsOS"

ENTRIES = (
    ("Analyse", "hunt a capture for threats", ("beacon", "scan", "tunnel", "dga")),
    ("Demo", "generate a labelled capture and hunt it", None),
    ("Beacons", "C2 callbacks only", ("beacon",)),
    ("Scans", "port and host sweeps only", ("scan",)),
    ("DNS", "tunneling and algorithmic domains", ("tunnel", "dga")),
    ("Tutorial", "how to use this tool", None),
    ("Quit", "", None),
)


def banner(title: str) -> str:
    label = f"   {title.upper()}  ·  {BRAND}   "
    rule = "═" * len(label)
    return (f"  ╔{rule}╗\n"
            f"  ║{label}║\n"
            f"  ╚{rule}╝")


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def clean_path(raw: str) -> str:
    """Make sense of a path a person typed, dragged, or pasted.

    Dragging a file into a terminal lands it backslash-escaped, and pasting one
    from elsewhere often brings quotes with it. Neither is a path, and failing
    on them would be the tool's fault rather than the user's.
    """
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    text = text.replace("\\ ", " ").replace("\\~", "~")
    return str(Path(text.strip()).expanduser())


def ask(prompt: str, default: str = "") -> str:
    shown = f"{prompt} [{default}]: " if default else f"{prompt}: "
    try:
        answer = input(f"   {shown}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return answer or default


def run(title: str, dispatch) -> int:
    """Loop the menu, handing (index, entry) to dispatch until the user quits.

    dispatch returns an exit status to stop on, or None to show the menu again.
    """
    while True:
        print()
        print(banner(title))
        for number, (name, blurb, _) in enumerate(ENTRIES, start=1):
            print(f"   {number}) {name:<15}{blurb}".rstrip())
        print()
        try:
            choice = input(f"   Pick 1-{len(ENTRIES)}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n   Done. See you next time.")
            return 0
        print()

        if choice in ("", "q", str(len(ENTRIES))):
            print("   Done. See you next time.")
            return 0
        if not choice.isdigit() or not 1 <= int(choice) <= len(ENTRIES):
            print(f"   Please type a number from 1 to {len(ENTRIES)}.")
            continue

        status = dispatch(int(choice), ENTRIES[int(choice) - 1])
        if status is not None:
            return status


TUTORIAL = """\
   pcapinator reads a packet capture and reports four things.

   Beaconing     an implant calling home on a schedule. Reported with the
                 period, the jitter, and how many callbacks were seen.
   Scans         one host sweeping many ports, or one port across many hosts.
   DNS tunneling data smuggled inside query names, with the estimated volume.
   DGA domains   algorithmically generated names, grouped per infected host.

   Getting a capture:
     sudo tcpdump -i any -w today.pcap        stop with control-c
     Wireshark: Capture, then File > Save As

   From the command line, which is the real interface:
     pcapi capture.pcap                       everything
     pcapi capture.pcap --only beacon         one detector
     pcapi capture.pcap --top 20              cap the output
     pcapi capture.pcap --json                for a script or a SIEM
     pcapi --demo demo.pcap                   labelled traffic to try it on

   Say which addresses are yours. Beaconing means one of your hosts calling
   out, and without this the tool cannot tell your side from theirs:
     pcapi capture.pcap --local-net 10.0.0.0/8 --local-net 192.168.0.0/16

   Two things worth knowing before you trust a result:

   A score says how strongly traffic is scheduled, not how malicious it is.
   A monitoring check that runs every ten seconds scores higher than most real
   implants. Read the evidence under each finding, not just the number.

   No findings does not mean no threat. A beacon slower than the capture
   leaves nothing to measure.
"""
