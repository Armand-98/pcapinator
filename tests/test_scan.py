"""Scan detector tests.

Traffic is synthesised with known ground truth. The negative cases carry the
weight here: every benign generator below is shaped like a scan on at least one
axis, and the detector has to reject it on the response signal. Every generator
is seeded, so a failure is always reproducible.
"""

import itertools
import math
import random

import pytest

from pcapinator.detect.scan import (
    HALF_OPEN,
    HORIZONTAL,
    MIN_FANOUT,
    VERTICAL,
    find_scans,
)
from pcapinator.layers.types import Flow, FlowKey

SCANNER = "10.0.0.66"
CLIENT = "10.0.0.5"
VICTIM = "10.0.0.9"

SYN = 0x02
REFUSED = 0x02 | 0x04 | 0x10        # SYN, then RST/ACK back
SESSION = 0x02 | 0x08 | 0x10 | 0x01  # a real connection that carried data

# Ephemeral source ports, recycled: a scan uses a fresh one per attempt, and
# grouping must not depend on them.
_ports = itertools.cycle(range(1024, 65536))


def flow(src, dst, dport, start, *, proto=6, responded=True, flags=SESSION,
         payload_out=900, payload_in=6000, duration=0.2):
    return Flow(
        key=FlowKey(proto, src, next(_ports), dst, dport),
        start=start, end=start + duration,
        packets_out=6 if responded else 2,
        packets_in=5 if responded else 0,
        bytes_out=payload_out + 300, bytes_in=payload_in + 300 if responded else 0,
        payload_out=payload_out,
        payload_in=payload_in if responded else 0,
        flags_seen=flags, responded=responded,
    )


# --- scan traffic ----------------------------------------------------------

def vertical_syn_scan(ports=400, *, base=1000.0, step=0.004, seed=1):
    """nmap -sS against one host: a bare SYN per port, nothing comes back."""
    rng = random.Random(seed)
    return [flow(SCANNER, VICTIM, port, base + index * step + rng.uniform(0, step / 4),
                 responded=False, flags=SYN, payload_out=0, duration=0.0)
            for index, port in enumerate(range(1, ports + 1))]


def vertical_connect_scan(ports=200, *, base=2000.0, step=0.01):
    """A connect() scan of a live host: every closed port answers with a RST.

    Flow.responded is True for all of these, which is why the response signal
    has to mean "became a session" rather than "got a packet back".
    """
    return [flow(SCANNER, VICTIM, port, base + index * step,
                 responded=True, flags=REFUSED, payload_out=0, payload_in=0)
            for index, port in enumerate(range(1, ports + 1))]


def horizontal_sweep(hosts=254, dport=445, *, base=3000.0, step=0.01,
                     responded=False, flags=SYN):
    return [flow(SCANNER, f"10.1.0.{index + 1}", dport, base + index * step,
                 responded=responded, flags=flags, payload_out=0, payload_in=0)
            for index in range(hosts)]


def ping_sweep(hosts=120, *, base=4000.0, step=0.02):
    return [flow(SCANNER, f"10.2.0.{index}", 0, base + index * step,
                 proto=1, responded=False, flags=0, payload_out=0, duration=0.0)
            for index in range(hosts)]


# --- benign traffic --------------------------------------------------------

def browsing(hosts=100, *, src=CLIENT, dport=443, base=5000.0, seed=7,
             fail_rate=0.0):
    """A hundred TLS connections to a hundred hosts: a horizontal scan's shape,
    separated only by the answers and the payload."""
    rng = random.Random(seed)
    flows, now = [], base
    for index in range(hosts):
        dead = rng.random() < fail_rate
        flows.append(flow(src, f"198.51.{index // 254}.{index % 254}", dport, now,
                          responded=not dead,
                          flags=SYN if dead else SESSION,
                          payload_out=0 if dead else rng.randint(500, 4000),
                          payload_in=rng.randint(2000, 90000)))
        now += rng.expovariate(1 / 1.5)
    return flows


def cdn_burst(hosts=40, *, base=6000.0, seed=11):
    """One page load fanning out to CDN hosts inside two seconds: fast and wide
    at the same time, which is exactly what a scan looks like on timing alone."""
    rng = random.Random(seed)
    return [flow(CLIENT, f"203.0.113.{index}", 443, base + rng.uniform(0, 2.0),
                 payload_out=rng.randint(400, 1500),
                 payload_in=rng.randint(1500, 40000))
            for index in range(hosts)]


def backup_job(connections=300, *, base=7000.0, step=0.05):
    """A sync job hammering one host and port: high rate, perfectly uniform, no
    fan-out at all."""
    return [flow(CLIENT, "10.0.0.20", 22, base + index * step,
                 payload_out=64000, payload_in=200)
            for index in range(connections)]


def nat_gateway(users=8, hosts=30, *, base=8000.0, seed=13):
    """Many users aggregated onto one source address, so one src fans out to
    hundreds of destinations on a handful of ports."""
    rng = random.Random(seed)
    flows = []
    for user in range(users):
        for index in range(hosts):
            flows.append(flow("198.51.100.1", f"93.184.{index}.{user}",
                              rng.choice([80, 443, 443, 443]),
                              base + rng.uniform(0, 600),
                              payload_out=rng.randint(300, 5000),
                              payload_in=rng.randint(1000, 120000)))
    return flows


def dead_service_retry(attempts=40, *, base=9000.0, step=5.0):
    """A client retrying a service that is down. Unanswered, empty and evenly
    spaced, but aimed at one target, so there is no fan-out to speak of."""
    return [flow(CLIENT, "10.0.0.30", 5432, base + index * step,
                 responded=False, flags=SYN, payload_out=0, duration=0.0)
            for index in range(attempts)]


def mail_client(*, base=9500.0):
    """One server, several services: fan-out below the floor."""
    return [flow(CLIENT, "10.0.0.40", port, base + index * 0.3)
            for index, port in enumerate([25, 143, 465, 587, 993, 995])]


def only(scans):
    assert len(scans) == 1, [s.describe() for s in scans]
    return scans[0]


# --- detection -------------------------------------------------------------

def test_half_open_vertical_scan_is_detected():
    scan = only(find_scans(vertical_syn_scan()))
    assert scan.kind == HALF_OPEN
    assert (scan.src, scan.dst, scan.dport) == (SCANNER, VICTIM, None)
    assert (scan.hosts, scan.ports) == (1, 400)
    assert scan.half_open_ratio == 1.0
    assert scan.response_score == 1.0
    assert scan.score > 0.95


def test_connect_scan_answered_by_resets_is_still_a_scan():
    """The loudest scan there is: every closed port replies. Counting a RST as a
    response would miss it entirely."""
    scan = only(find_scans(vertical_connect_scan()))
    assert scan.kind == VERTICAL
    assert scan.half_open_ratio == 0.0
    assert scan.response_score == 1.0
    assert scan.score > 0.9


def test_horizontal_sweep_is_detected():
    scan = only(find_scans(horizontal_sweep()))
    assert scan.kind == HALF_OPEN
    assert (scan.dst, scan.dport) == (None, 445)
    assert (scan.hosts, scan.ports) == (254, 1)
    assert scan.score > 0.95


def test_horizontal_sweep_of_refusing_hosts_is_horizontal_not_half_open():
    scan = only(find_scans(horizontal_sweep(responded=True, flags=REFUSED)))
    assert scan.kind == HORIZONTAL
    assert scan.hosts == 254


def test_icmp_ping_sweep_is_horizontal():
    scan = only(find_scans(ping_sweep()))
    assert scan.kind == HORIZONTAL
    assert (scan.proto, scan.dport, scan.hosts) == (1, 0, 120)


def test_slow_scan_is_still_detected():
    """One connection every five seconds defeats rate thresholds. Timing is only
    supporting evidence, so the sweep still stands out."""
    scans = find_scans(vertical_syn_scan(ports=30, step=5.0, seed=2))
    scan = only(scans)
    assert scan.rate < 0.25
    assert scan.timing_score < 0.5
    assert scan.score > 0.8


def test_scan_just_above_the_fanout_floor_is_detected():
    scan = only(find_scans(vertical_syn_scan(ports=MIN_FANOUT)))
    assert scan.ports == MIN_FANOUT


def test_block_sweep_is_reported_on_both_axes():
    """Many hosts times many ports is genuinely both shapes; each result answers
    a different question, so both views are kept."""
    flows = [flow(SCANNER, f"10.3.0.{host}", port, 10000.0 + n * 0.005,
                  responded=False, flags=SYN, payload_out=0, duration=0.0)
             for n, (host, port) in enumerate(
                 (h, p) for h in range(20) for p in range(20, 40))]
    scans = find_scans(flows)
    assert len(scans) == 40
    assert {s.hosts for s in scans} == {1, 20}
    assert all(s.kind == HALF_OPEN for s in scans)


def test_scanner_is_found_in_a_capture_full_of_normal_traffic():
    flows = (browsing() + cdn_burst() + backup_job() + nat_gateway()
             + vertical_syn_scan(ports=120))
    scan = only(find_scans(flows))
    assert scan.src == SCANNER


# --- rejection -------------------------------------------------------------

def test_browsing_a_hundred_hosts_on_443_is_not_a_scan():
    assert find_scans(browsing()) == []


def test_browsing_with_some_dead_hosts_is_not_a_scan():
    assert find_scans(browsing(hosts=150, seed=17, fail_rate=0.12)) == []


def test_cdn_burst_is_not_a_scan():
    assert find_scans(cdn_burst()) == []


def test_backup_job_is_not_a_scan():
    assert find_scans(backup_job()) == []


def test_nat_gateway_is_not_a_scan():
    assert find_scans(nat_gateway()) == []


def test_retrying_a_dead_service_is_not_a_scan():
    """Unanswered, empty and metronomic, and still not a scan: no fan-out."""
    assert find_scans(dead_service_retry()) == []


def test_mail_client_touching_several_ports_is_not_a_scan():
    assert find_scans(mail_client()) == []


def test_fanout_below_the_floor_is_never_a_scan():
    assert find_scans(vertical_syn_scan(ports=MIN_FANOUT - 1)) == []


def test_wide_unanswered_fanout_below_the_floor_stays_quiet():
    assert find_scans(horizontal_sweep(hosts=MIN_FANOUT - 1)) == []


def test_threshold_is_respected():
    flows = vertical_syn_scan(ports=40)
    assert find_scans(flows, threshold=0.99) == []
    assert find_scans(flows, threshold=0.5)


def test_min_fanout_is_overridable():
    assert find_scans(vertical_syn_scan(ports=5), min_fanout=4)


# --- ordering and robustness ----------------------------------------------

def test_results_are_ordered_worst_first():
    flows = (vertical_syn_scan(ports=300)
             + [flow("10.0.0.77", "10.0.0.9", port, 20000.0 + i * 0.5,
                     responded=False, flags=SYN, payload_out=0)
                for i, port in enumerate(range(1, 13))])
    scans = find_scans(flows)
    assert len(scans) == 2
    assert scans[0].score >= scans[1].score
    assert scans[0].src == SCANNER


def test_every_component_score_is_reported_and_bounded():
    scan = only(find_scans(vertical_syn_scan(ports=64)))
    components = (scan.fanout_score, scan.response_score,
                  scan.timing_score, scan.payload_score, scan.half_open_ratio)
    assert all(0.0 <= value <= 1.0 for value in components)
    assert scan.fanout_score == pytest.approx(1.0)
    assert scan.first < scan.last
    assert scan.attempts == 64 and scan.fanout == 64
    assert scan.describe()


def test_empty_input_is_handled():
    assert find_scans([]) == []


def test_simultaneous_attempts_do_not_divide_by_zero():
    flows = [flow(SCANNER, VICTIM, port, 1000.0, responded=False, flags=SYN,
                  payload_out=0, duration=0.0) for port in range(1, 50)]
    scan = only(find_scans(flows))
    assert scan.rate == math.inf
    assert scan.duration == 0.0
    assert scan.score > 0.9


def test_absurd_timestamps_do_not_raise():
    """Capture timestamps come from an untrusted file and can be anything."""
    junk = [math.inf, -math.inf, math.nan, 0.0, 1e18, -1e18]
    flows = [flow(SCANNER, VICTIM, port, junk[port % len(junk)],
                  responded=False, flags=SYN, payload_out=0, duration=0.0)
             for port in range(1, 40)]
    for scan in find_scans(flows):
        assert 0.0 <= scan.score <= 1.0


def test_state_stays_bounded_on_a_huge_scan():
    from pcapinator.detect.scan import MAX_STARTS
    scan = only(find_scans(vertical_syn_scan(ports=MAX_STARTS + 1500, step=0.001)))
    assert scan.attempts == MAX_STARTS + 1500
    assert scan.score > 0.9


def test_answered_connections_are_served_even_when_the_server_sends_no_data():
    """A completed handshake proves the port is open.

    Counting only connections that returned payload made any protocol where the
    server replies without data look maximally scan-like, which flagged plain
    web browsing across sixty hosts as a horizontal scan.
    """
    from pcapinator.detect.scan import find_scans
    from pcapinator.layers.types import Flow, FlowKey, TCP_ACK, TCP_SYN

    flows = [
        Flow(key=FlowKey(6, "10.0.0.12", 50000 + i, f"198.51.100.{i}", 443),
             start=1000.0 + i * 0.05, end=1000.5 + i * 0.05,
             packets_out=4, packets_in=3,
             bytes_out=900, bytes_in=300,
             payload_out=400, payload_in=0,
             flags_seen=TCP_SYN | TCP_ACK, responded=True)
        for i in range(80)
    ]
    assert find_scans(flows) == []

    scored = find_scans(flows, threshold=0.0)
    assert all(s.response_score == 0.0 for s in scored), (
        "nothing went unserved, so the unserved share must be zero")


# --- sessions and streams that carry no server payload ---------------------
#
# Every generator below is wide, fast and answered by no data at all, which is
# the whole of the scan signal if "unanswered" is read as "returned nothing".
# None of them is a search for a service that is not there.

EMPTY_SESSION = 0x02 | 0x10 | 0x01   # SYN, ACK, FIN and not one byte of data
PUSH = 0x08 | 0x10                   # mid-capture: the handshake is not in the file


def health_checks(hosts=40, rounds=12, *, base=11000.0):
    """A load balancer TCP checking every backend every five seconds."""
    return [flow("10.0.1.5", f"10.0.2.{host}", 8080,
                 base + round_ * 5.0 + host * 0.01, flags=EMPTY_SESSION,
                 payload_out=0, payload_in=0, duration=0.01)
            for round_ in range(rounds) for host in range(hosts)]


def bulk_upload(hosts=20, *, base=12000.0, flags=SESSION):
    """A log shipper or backup client pushing to storage nodes. The peer sends
    nothing but ACKs, so there is no inbound payload anywhere in the fan-out."""
    return [flow("10.0.1.6", f"10.0.3.{host}", 9000, base + host * 0.3,
                 flags=flags, payload_out=4_000_000, payload_in=0, duration=8.0)
            for host in range(hosts)]


def multicast_stream(groups=30, *, base=13000.0):
    """A market data or video source fanning out to multicast groups: one way,
    thirty destinations on one port, and nothing ever answers a multicast."""
    return [flow("10.0.1.7", f"239.1.2.{group}", 5004, base + group * 0.02,
                 proto=17, responded=False, flags=0, payload_out=1_400_000,
                 duration=30.0)
            for group in range(groups)]


def fragmented_replies(clients=50, *, base=14000.0):
    """Fragments carry no ports, so a server's large UDP answers form their own
    port-0 flows out to every client: a horizontal sweep on port 0 by shape."""
    return [flow("10.0.1.8", f"10.0.4.{client}", 0, base + client * 0.05,
                 proto=17, responded=False, flags=0, payload_out=2800,
                 duration=0.001)
            for client in range(clients)]


def wake_on_lan(hosts=40, *, base=15000.0):
    """A management host waking a fleet: wide, fast, one way, and answered by
    nothing at all. Only the payload separates it from a UDP sweep."""
    return [flow("10.0.1.9", f"10.0.8.{host}", 9, base + host * 0.05, proto=17,
                 responded=False, flags=0, payload_out=102, duration=0.0)
            for host in range(hosts)]


def test_tcp_health_checks_are_not_a_scan():
    """480 empty connections over 40 backends. The handshake completing is the
    only evidence that the port was open, and it has to be enough."""
    assert find_scans(health_checks()) == []


def test_one_way_upload_fanout_is_not_a_scan():
    assert find_scans(bulk_upload()) == []


def test_upload_whose_handshake_predates_the_capture_is_not_a_scan():
    assert find_scans(bulk_upload(base=12500.0, flags=PUSH)) == []


def test_multicast_stream_is_not_a_scan():
    assert find_scans(multicast_stream()) == []


def test_fragmented_udp_replies_are_not_a_scan():
    assert find_scans(fragmented_replies()) == []


def test_wake_on_lan_sweep_is_not_a_scan():
    assert find_scans(wake_on_lan()) == []


def test_none_of_the_payload_free_traffic_fires_together():
    flows = (health_checks() + bulk_upload() + multicast_stream()
             + fragmented_replies() + wake_on_lan() + browsing())
    assert find_scans(flows) == []
    scan = only(find_scans(flows + horizontal_sweep(hosts=60, dport=3389)))
    assert scan.src == SCANNER


def test_a_lone_syn_ack_is_not_a_served_session():
    """A stealth scan of a host whose ports are all open draws one SYN-ACK per
    probe and nothing else. One packet back is what a refusal looks like too, so
    it cannot count as service, or the scan disappears."""
    flows = [Flow(key=FlowKey(6, SCANNER, 40000 + port, VICTIM, port),
                  start=16000.0 + port * 0.01, end=16000.0 + port * 0.01,
                  packets_out=1, packets_in=1, bytes_out=60, bytes_in=60,
                  payload_out=0, payload_in=0,
                  flags_seen=0x02 | 0x10, responded=True)
             for port in range(1, 121)]
    scan = only(find_scans(flows))
    assert scan.response_score == 1.0
    assert scan.score > 0.9


def test_udp_sweep_with_empty_probes_is_detected():
    """The payload gate is a gate, not a veto: nmap sends an empty datagram to
    every UDP port it has no protocol probe for, which is most of them."""
    scan = only(find_scans(
        [flow(SCANNER, VICTIM, port, 17000.0 + port * 0.01, proto=17,
              responded=False, flags=0, payload_out=0, duration=0.0)
         for port in range(1, 200)]))
    assert scan.kind == VERTICAL
    assert scan.score > 0.9
