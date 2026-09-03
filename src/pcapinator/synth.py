"""Synthetic capture generation with known ground truth.

Evaluating a detector needs traffic whose answer is known in advance. Public
malware captures supply real positives but no negatives, and no labelled
benign baseline, so measuring a false positive rate against them is impossible.

Scenarios here generate both: the threat, and benign traffic deliberately shaped
to resemble it. Every generator is seeded, so a reported score can be reproduced
exactly. This is also what backs the tool's demo capture, so a user can confirm
the detectors work without first finding malware samples.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .layers.types import IPPROTO_TCP, IPPROTO_UDP

SYN, SYN_ACK, PSH_ACK, ACK, FIN_ACK, RST_ACK = 0x02, 0x12, 0x18, 0x10, 0x11, 0x14

Frames = list[tuple[float, bytes]]


@dataclass(frozen=True, slots=True)
class Truth:
    """One finding a correct detector must report for a scenario."""
    kind: str            # beacon | scan | tunnel | dga
    src: str
    dst: str = ""
    dport: int = 0
    detail: str = ""


@dataclass(slots=True)
class Scenario:
    name: str
    frames: Frames = field(default_factory=list)
    truth: list[Truth] = field(default_factory=list)
    # Detectors that legitimately fire on this benign scenario. Scripted
    # traffic is periodic by construction, so a beacon detector reports it and
    # is right to; recording that here keeps an honest finding from being
    # scored as an error, and keeps it visible instead of quietly suppressed.
    tolerated: tuple[str, ...] = ()

    def write(self, path: str | Path) -> Path:
        return write_pcap(path, self.frames)


# --- wire format builders --------------------------------------------------

def ip_bytes(addr: str) -> bytes:
    return bytes(int(part) for part in addr.split("."))


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
            + struct.pack("!H", ethertype) + payload)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0x4000,
                         ttl, proto, 0)
    return header + ip_bytes(src) + ip_bytes(dst) + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, flags,
                       8192, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("latin-1")
                      for part in name.split(".") if part) + b"\x00"
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + labels + struct.pack("!HH", qtype, 1))


def dns_response(name: str, qtype: int = 1, rcode: int = 0,
                 txid: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("latin-1")
                      for part in name.split(".") if part) + b"\x00"
    return (struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, 0, 0, 0)
            + labels + struct.pack("!HH", qtype, 1))


def write_pcap(path: str | Path, frames: Frames, linktype: int = 1) -> Path:
    path = Path(path)
    out = [b"\xd4\xc3\xb2\xa1", struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)]
    for ts, data in sorted(frames):
        sec = int(ts)
        out.append(struct.pack("<IIII", sec, int(round((ts - sec) * 1_000_000)),
                               len(data), len(data)))
        out.append(data)
    path.write_bytes(b"".join(out))
    return path


# --- conversation shapes ---------------------------------------------------

def tcp_session(ts: float, src: str, dst: str, sport: int, dport: int,
                payload_size: int, *, gap: float = 0.02,
                answered: bool = True, response_size: int = 0) -> Frames:
    """A complete short-lived TCP connection, or a SYN nobody answers.

    response_size matters more than it looks. A session where only the client
    ever sends data is not what real traffic looks like: a web server answers a
    small request with a large response. Generating one-sided sessions makes
    benign traffic resemble scanning, so every caller states what comes back.
    """
    if not answered:
        return [(ts, ethernet(ipv4(src, dst, IPPROTO_TCP, tcp(sport, dport, SYN))))]

    steps = [
        (src, dst, sport, dport, SYN, b""),
        (dst, src, dport, sport, SYN_ACK, b""),
        (src, dst, sport, dport, PSH_ACK, b"\x00" * payload_size),
        (dst, src, dport, sport, PSH_ACK, b"\x00" * response_size),
        (src, dst, sport, dport, FIN_ACK, b""),
        (dst, src, dport, sport, FIN_ACK, b""),
    ]
    return [(ts + index * gap,
             ethernet(ipv4(a, b, IPPROTO_TCP, tcp(sp, dp, flags, body))))
            for index, (a, b, sp, dp, flags, body) in enumerate(steps)]


def dns_exchange(ts: float, client: str, resolver: str, name: str, *,
                 qtype: int = 1, rcode: int = 0, sport: int = 53000) -> Frames:
    return [
        (ts, ethernet(ipv4(client, resolver, IPPROTO_UDP,
                           udp(sport, 53, dns_query(name, qtype))))),
        (ts + 0.01, ethernet(ipv4(resolver, client, IPPROTO_UDP,
                                  udp(53, sport, dns_response(name, qtype, rcode))))),
    ]


# --- threats ---------------------------------------------------------------

def beacon(src: str, dst: str, dport: int, *, period: float, count: int,
           jitter: float = 0.0, payload: int = 512, start: float = 1000.0,
           seed: int = 1) -> Scenario:
    rng = random.Random(seed)
    frames: Frames = []
    now = start
    for index in range(count):
        frames += tcp_session(now, src, dst, 40000 + index, dport, payload,
                              response_size=64)
        now += period * (1 + rng.uniform(-jitter, jitter))
    detail = f"period={period}s jitter={jitter:.0%} count={count}"
    return Scenario("beacon", frames, [Truth("beacon", src, dst, dport, detail)])


def vertical_scan(src: str, dst: str, *, ports: int = 400,
                  start: float = 1000.0, rate: float = 0.004,
                  open_ports: tuple[int, ...] = (22, 80, 443)) -> Scenario:
    frames: Frames = []
    for index, port in enumerate(range(1, ports + 1)):
        ts = start + index * rate
        frames += tcp_session(ts, src, dst, 41000 + index, port, 0,
                              answered=port in open_ports)
    return Scenario("vertical_scan", frames,
                    [Truth("scan", src, dst, 0, f"vertical, {ports} ports")])


def horizontal_scan(src: str, subnet: str, dport: int, *, hosts: int = 200,
                    start: float = 1000.0, rate: float = 0.004,
                    live: tuple[int, ...] = (10, 20, 30)) -> Scenario:
    frames: Frames = []
    for index in range(1, hosts + 1):
        dst = f"{subnet}.{index}"
        frames += tcp_session(start + index * rate, src, dst, 42000 + index,
                              dport, 0, answered=index in live)
    return Scenario("horizontal_scan", frames,
                    [Truth("scan", src, "", dport, f"horizontal, {hosts} hosts")])


def dns_tunnel(client: str, resolver: str, parent: str, *, queries: int = 300,
               start: float = 1000.0, rate: float = 0.5,
               seed: int = 2) -> Scenario:
    """Base32-looking payload in the leftmost labels, the shape iodine produces."""
    rng = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    frames: Frames = []
    now = start
    for index in range(queries):
        chunk = "".join(rng.choice(alphabet) for _ in range(48))
        name = f"{chunk[:24]}.{chunk[24:]}.t.{parent}"
        frames += dns_exchange(now, client, resolver, name,
                               qtype=16, rcode=3, sport=53000 + (index % 64))
        now += rate * rng.uniform(0.3, 2.2)
    return Scenario("dns_tunnel", frames,
                    [Truth("tunnel", client, parent, 53, f"{queries} queries")])


def dga_lookups(client: str, resolver: str, *, count: int = 60,
                start: float = 1000.0, seed: int = 3) -> Scenario:
    rng = random.Random(seed)
    frames: Frames = []
    names = []
    now = start
    for index in range(count):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz")
                        for _ in range(rng.randint(12, 18)))
        name = f"{label}.com"
        names.append(name)
        frames += dns_exchange(now, client, resolver, name,
                               rcode=3, sport=53000 + (index % 64))
        now += rng.expovariate(1 / 2.0)
    # One infected host is one finding however many domains it walks through,
    # which is how the report groups them.
    return Scenario("dga", frames,
                    [Truth("dga", client, "", 53, f"{len(names)} domains")])


# --- benign traffic shaped like the threats --------------------------------

def browsing(src: str, hosts: int = 60, *, start: float = 1000.0,
             seed: int = 4) -> Scenario:
    """Wide fan-out on 443 with real payloads and real answers: shaped like a
    horizontal scan, separated only by responses and payload."""
    rng = random.Random(seed)
    frames: Frames = []
    now = start
    for index in range(hosts):
        now += rng.expovariate(1 / 8.0)
        dst = f"198.51.100.{1 + index % 250}"
        for request in range(rng.randint(1, 4)):
            frames += tcp_session(now + request * rng.uniform(0.1, 2.0), src, dst,
                                  50000 + index * 8 + request, 443,
                                  rng.randint(300, 1200),
                                  response_size=rng.randint(2000, 60000))
    return Scenario("browsing", frames, [])


def cdn_lookups(client: str, resolver: str, *, count: int = 400,
                start: float = 1000.0, seed: int = 5) -> Scenario:
    """High subdomain cardinality under one parent, which is what a CDN looks
    like and what a naive tunnel detector flags."""
    rng = random.Random(seed)
    frames: Frames = []
    now = start
    for index in range(count):
        name = (f"media-{rng.randint(1, 9999)}-{rng.choice(['eu', 'us', 'ap'])}"
                f".cdn.example.net")
        frames += dns_exchange(now, client, resolver, name,
                               sport=53000 + (index % 64))
        now += rng.expovariate(1 / 0.4)
    return Scenario("cdn_lookups", frames, [])


def reverse_sweep(client: str, resolver: str, *, hosts: int = 254,
                  start: float = 1000.0) -> Scenario:
    """in-addr.arpa sweep: high cardinality, highly numeric, entirely benign."""
    frames: Frames = []
    for index in range(1, hosts + 1):
        name = f"{index}.100.51.198.in-addr.arpa"
        frames += dns_exchange(start + index * 0.05, client, resolver, name,
                               qtype=12, rcode=3 if index % 3 else 0,
                               sport=53000 + (index % 64))
    return Scenario("reverse_sweep", frames, [], tolerated=("beacon",))


def health_checks(src: str, dst: str, dport: int, *, count: int = 200,
                  start: float = 1000.0) -> Scenario:
    """A monitor polling one service on a fixed interval. Genuinely periodic and
    genuinely benign: the hardest negative for a beacon detector, and the reason
    findings need context rather than being taken as verdicts."""
    frames: Frames = []
    for index in range(count):
        frames += tcp_session(start + index * 10.0, src, dst,
                              43000 + index, dport, 64, response_size=128)
    return Scenario("health_checks", frames, [], tolerated=("beacon",))


def merge(name: str, *scenarios: Scenario) -> Scenario:
    frames: Frames = []
    truth: list[Truth] = []
    for scenario in scenarios:
        frames += scenario.frames
        truth += scenario.truth
    return Scenario(name, frames, truth)
