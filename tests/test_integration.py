"""End to end tests over real capture bytes.

Each module is unit tested in isolation, which does not prove they compose. A
synthetic capture is built here frame by frame, written as a real pcap file, and
pushed through the whole pipeline: read_packets -> decode -> assemble ->
find_beacons. Ground truth is known because the traffic was generated here.
"""

import random
import struct

import pytest

from pcapinator.detect.beacon import find_beacons
from pcapinator.flows import assemble
from pcapinator.layers import decode
from pcapinator.layers.dns import parse_dns
from pcapinator.layers.types import IPPROTO_TCP, IPPROTO_UDP
from pcapinator.pcap import read_packets

CLIENT = "10.0.0.5"
C2 = "203.0.113.9"
WEB = "198.51.100.20"

SYN, SYN_ACK, PSH_ACK, ACK, FIN_ACK = 0x02, 0x12, 0x18, 0x10, 0x11


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def ethernet(payload, ethertype=0x0800):
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" \
        + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ttl=64):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, ttl, proto, 0)
    return header + ip_bytes(src) + ip_bytes(dst) + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, flags,
                       8192, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name, qtype=1, txid=0x1234):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) \
        + labels + struct.pack("!HH", qtype, 1)


def write_pcap(path, frames, linktype=1):
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype)
    for ts, data in frames:
        sec, usec = int(ts), int(round((ts - int(ts)) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(data), len(data)) + data
    path.write_bytes(out)
    return path


def tcp_session(ts, sport, dst, dport, payload_size, *, gap=0.05):
    """One complete short-lived TCP connection, the shape of a C2 check-in."""
    body = b"\x00" * payload_size
    steps = [
        (CLIENT, dst, sport, dport, SYN, b""),
        (dst, CLIENT, dport, sport, SYN_ACK, b""),
        (CLIENT, dst, sport, dport, PSH_ACK, body),
        (dst, CLIENT, dport, sport, ACK, b""),
        (CLIENT, dst, sport, dport, FIN_ACK, b""),
        (dst, CLIENT, dport, sport, FIN_ACK, b""),
    ]
    frames = []
    for index, (src, dest, sp, dp, flags, data) in enumerate(steps):
        segment = tcp(sp, dp, flags, data)
        frames.append((ts + index * gap,
                       ethernet(ipv4(src, dest, IPPROTO_TCP, segment))))
    return frames


def run(path, **kw):
    frames = (frame for frame in
              (decode(packet) for packet in read_packets(path)) if frame)
    return list(assemble(frames, **kw))


# --- the headline case -----------------------------------------------------

def test_beacon_is_recovered_from_a_real_capture_file(tmp_path):
    frames = []
    for index in range(40):
        frames += tcp_session(1000.0 + index * 60.0, 40000 + index, C2, 443, 512)

    flows = run(write_pcap(tmp_path / "beacon.pcap", sorted(frames)))
    beacons = find_beacons(flows)

    assert len(beacons) == 1
    assert (beacons[0].src, beacons[0].dst, beacons[0].dport) == (CLIENT, C2, 443)
    assert beacons[0].period == pytest.approx(60.0, abs=1.0)
    assert beacons[0].connections == 40
    assert beacons[0].score > 0.9


def test_beacon_is_found_amongst_browsing_noise(tmp_path):
    """The discriminating case: a beacon must be picked out of ordinary traffic
    to the same host mix, not just detected in a clean laboratory capture."""
    rng = random.Random(4)
    frames = []
    for index in range(40):
        frames += tcp_session(1000.0 + index * 60.0, 40000 + index, C2, 443, 512)

    now = 1000.0
    for index in range(60):
        now += rng.expovariate(1 / 35.0)
        frames += tcp_session(now, 50000 + index, WEB, 443, rng.randint(200, 40000))

    flows = run(write_pcap(tmp_path / "mixed.pcap", sorted(frames)))
    beacons = find_beacons(flows)

    assert [b.dst for b in beacons] == [C2], "browsing traffic must not be flagged"


def test_jittered_beacon_survives_the_full_pipeline(tmp_path):
    rng = random.Random(21)
    frames, now = [], 1000.0
    for index in range(50):
        frames += tcp_session(now, 40000 + index, C2, 8443, 300)
        now += 45.0 * (1 + rng.uniform(-0.25, 0.25))

    flows = run(write_pcap(tmp_path / "jitter.pcap", sorted(frames)))
    (beacon,) = find_beacons(flows)
    assert beacon.period == pytest.approx(45.0, rel=0.15)
    assert beacon.dport == 8443


# --- the pipeline itself ---------------------------------------------------

def test_each_checkin_becomes_its_own_flow(tmp_path):
    """Beacon detection depends entirely on callbacks appearing as separate
    connections rather than one long-lived conversation."""
    frames = []
    for index in range(12):
        frames += tcp_session(1000.0 + index * 30.0, 40000 + index, C2, 443, 256)

    flows = run(write_pcap(tmp_path / "split.pcap", sorted(frames)))
    to_c2 = [f for f in flows if f.key.dst == C2]
    assert len(to_c2) == 12
    assert all(f.responded for f in to_c2)
    assert all(f.payload_out == 256 for f in to_c2)


def test_flow_orientation_follows_the_syn(tmp_path):
    frames = tcp_session(1000.0, 40000, C2, 443, 128)
    (flow,) = run(write_pcap(tmp_path / "orient.pcap", frames))
    assert flow.key.src == CLIENT and flow.key.dst == C2
    assert flow.key.dport == 443
    assert flow.packets_out == 3 and flow.packets_in == 3


def test_udp_and_dns_traverse_the_pipeline(tmp_path):
    query = dns_query("beacon.evil.example")
    frame = ethernet(ipv4(CLIENT, "8.8.8.8", IPPROTO_UDP, udp(53000, 53, query)))
    path = write_pcap(tmp_path / "dns.pcap", [(1000.0, frame)])

    packets = list(read_packets(path))
    decoded = decode(packets[0])
    assert decoded.proto == IPPROTO_UDP and decoded.dport == 53

    message = parse_dns(decoded.payload)
    assert message is not None
    assert message.questions[0].name == "beacon.evil.example"


def test_capture_with_no_beacons_yields_nothing(tmp_path):
    rng = random.Random(99)
    frames, now = [], 1000.0
    for index in range(80):
        now += rng.expovariate(1 / 30.0)
        frames += tcp_session(now, 50000 + index, WEB, 443, rng.randint(100, 50000))

    flows = run(write_pcap(tmp_path / "clean.pcap", sorted(frames)))
    assert find_beacons(flows) == []


def test_truncated_capture_still_yields_usable_flows(tmp_path):
    """Captures killed mid-write are routine; the pipeline must degrade rather
    than fail."""
    frames = []
    for index in range(12):
        frames += tcp_session(1000.0 + index * 30.0, 40000 + index, C2, 443, 256)
    path = write_pcap(tmp_path / "cut.pcap", sorted(frames))
    path.write_bytes(path.read_bytes()[:-37])

    flows = run(path)
    assert len(flows) >= 11


# --- what the score does and does not mean ---------------------------------

def test_benign_periodic_traffic_is_reported_and_scoped_not_suppressed(tmp_path):
    """A health-check monitor is a near perfect beacon and scores higher than a
    real implant. Timing alone cannot separate them, so the detector reports
    both and records the destination scope for the report to rank on. Hiding
    internal destinations here would hide lateral movement."""
    from pcapinator.synth import beacon, health_checks, merge

    scenario = merge(
        "mixed",
        beacon(CLIENT, C2, 443, period=60.0, count=40, jitter=0.15),
        health_checks("10.0.0.9", "10.0.0.20", 8080, count=120),
    )
    flows = run(scenario.write(tmp_path / "mixed.pcap"))
    found = {b.dst: b for b in find_beacons(flows)}

    assert set(found) == {C2, "10.0.0.20"}
    # On the timing signal itself the monitor is the cleaner beacon of the two,
    # which is the point: periodicity cannot tell them apart.
    assert found["10.0.0.20"].interval_score == 1.0
    assert found["10.0.0.20"].interval_score >= found[C2].interval_score
    assert found[C2].dst_scope == "external"
    assert found["10.0.0.20"].dst_scope == "private"


@pytest.mark.parametrize("address,expected", [
    ("203.0.113.9", "external"),
    ("10.0.0.20", "private"),
    ("192.168.1.5", "private"),
    ("172.16.4.4", "private"),
    ("127.0.0.1", "loopback"),
    ("169.254.1.1", "link-local"),
    ("224.0.0.251", "multicast"),
    ("not-an-address", "unknown"),
])
def test_destination_scope_classification(address, expected):
    from pcapinator.detect.beacon import scope
    assert scope(address) == expected
