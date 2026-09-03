"""Beacon detector tests.

Traffic is synthesised with known ground truth: schedules the detector must
find, and human-shaped activity it must leave alone. Every generator is seeded,
so a failure is always reproducible.
"""

import random

import pytest

from pcapinator.detect.beacon import MIN_CONNECTIONS, find_beacons, score_group
from pcapinator.layers.types import Flow, FlowKey

SRC = "10.0.0.5"
DST = "203.0.113.9"


def make_flows(starts, *, src=SRC, dst=DST, dport=443, proto=6,
               payload=512, payloads=None):
    flows = []
    for index, start in enumerate(starts):
        size = payloads[index] if payloads is not None else payload
        # Ephemeral source ports differ per connection, which is exactly why
        # beacons are grouped on (src, dst, dport) rather than the full tuple.
        key = FlowKey(proto, src, 40000 + index, dst, dport)
        flows.append(Flow(key=key, start=start, end=start + 0.2,
                          packets_out=5, packets_in=4,
                          bytes_out=size + 200, bytes_in=300,
                          payload_out=size, payload_in=100,
                          flags_seen=0x12, responded=True))
    return flows


def beacon_starts(period, count, *, jitter=0.0, seed=1, base=1000.0):
    rng = random.Random(seed)
    starts, now = [], base
    for _ in range(count):
        starts.append(now)
        now += period + rng.uniform(-jitter, jitter) * period
    return starts


def human_starts(count, *, seed=7, base=1000.0, mean=45.0):
    """Poisson-ish arrivals: the right null hypothesis for user driven traffic."""
    rng = random.Random(seed)
    starts, now = [], base
    for _ in range(count):
        starts.append(now)
        now += rng.expovariate(1.0 / mean)
    return starts


def only(beacons):
    assert len(beacons) == 1, f"expected exactly one beacon, got {len(beacons)}"
    return beacons[0]


# --- detection -------------------------------------------------------------

def test_perfect_schedule_is_detected_with_its_period():
    beacon = only(find_beacons(make_flows(beacon_starts(60.0, 40))))
    assert beacon.period == pytest.approx(60.0, abs=0.5)
    assert beacon.jitter == pytest.approx(0.0, abs=0.5)
    assert beacon.connections == 40
    assert beacon.score > 0.9
    assert (beacon.src, beacon.dst, beacon.dport) == (SRC, DST, 443)


@pytest.mark.parametrize("jitter", [0.05, 0.10, 0.20, 0.30])
def test_jittered_beacons_survive_realistic_jitter(jitter):
    """Every real C2 framework randomises its callback. Identical-interval
    matching would find none of these."""
    starts = beacon_starts(60.0, 60, jitter=jitter, seed=int(jitter * 100))
    beacon = only(find_beacons(make_flows(starts)))
    assert beacon.period == pytest.approx(60.0, rel=0.15)
    assert beacon.score > 0.7


def test_missed_checkins_are_folded_not_penalised():
    """An implant on a sleeping laptop skips callbacks. The resulting 2x and 3x
    gaps are evidence for the schedule, not against it."""
    rng = random.Random(3)
    starts, now = [], 1000.0
    missed = 0
    for _ in range(60):
        starts.append(now)
        skips = 0 if rng.random() > 0.25 else rng.choice([1, 2])
        missed += skips
        now += 60.0 * (1 + skips)
    beacon = only(find_beacons(make_flows(starts)))
    assert beacon.period == pytest.approx(60.0, abs=1.0)
    assert beacon.missed == missed
    assert beacon.score > 0.85


def test_period_recovered_when_most_checkins_are_missed():
    """With over half the callbacks gone the median interval sits on a multiple
    of the true period, so the estimator must climb back down to the base."""
    rng = random.Random(11)
    starts, now = [], 1000.0
    for _ in range(50):
        starts.append(now)
        now += 30.0 * rng.choice([1, 2, 2, 3, 3, 4])
    beacon = only(find_beacons(make_flows(starts)))
    assert beacon.period == pytest.approx(30.0, abs=1.5)


def test_slow_beacon_over_a_long_capture():
    beacon = only(find_beacons(make_flows(beacon_starts(3600.0, 24, jitter=0.05))))
    assert beacon.period == pytest.approx(3600.0, rel=0.1)


# --- rejection -------------------------------------------------------------

def test_human_traffic_is_not_flagged():
    assert find_beacons(make_flows(human_starts(80))) == []


def test_human_traffic_with_varying_payloads_is_not_flagged():
    starts = human_starts(80, seed=13)
    rng = random.Random(13)
    sizes = [rng.randint(200, 60000) for _ in starts]
    assert find_beacons(make_flows(starts, payloads=sizes)) == []


def test_too_few_connections_is_never_a_beacon():
    starts = beacon_starts(60.0, MIN_CONNECTIONS - 1)
    assert find_beacons(make_flows(starts)) == []


def test_a_short_regular_burst_scores_below_a_full_length_beacon():
    """Regularity alone is not enough; a beacon should hold its schedule across
    the capture rather than for ninety seconds of it."""
    window = make_flows(beacon_starts(600.0, 30), dst="198.51.100.7", dport=80)
    burst = make_flows(beacon_starts(3.0, 30), dst="198.51.100.9", dport=8080)
    scored = {b.dst: b.score for b in find_beacons(window + burst, threshold=0.0)}
    assert scored["198.51.100.7"] > scored["198.51.100.9"]


def test_inconsistent_payload_sizes_lower_the_score():
    starts = beacon_starts(60.0, 40)
    rng = random.Random(5)
    noisy = [rng.randint(100, 80000) for _ in starts]
    steady = find_beacons(make_flows(starts), threshold=0.0)[0]
    varied = find_beacons(make_flows(starts, payloads=noisy), threshold=0.0)[0]
    assert varied.size_score < steady.size_score
    assert varied.score < steady.score


# --- grouping and shape ----------------------------------------------------

def test_conversations_are_scored_independently():
    flows = (make_flows(beacon_starts(60.0, 40), dst="203.0.113.1")
             + make_flows(human_starts(60), dst="203.0.113.2"))
    beacons = find_beacons(flows)
    assert [b.dst for b in beacons] == ["203.0.113.1"]


def test_results_are_ordered_by_score():
    flows = (make_flows(beacon_starts(60.0, 40), dst="203.0.113.1")
             + make_flows(beacon_starts(60.0, 40, jitter=0.3, seed=9),
                          dst="203.0.113.2"))
    scores = [b.score for b in find_beacons(flows, threshold=0.0)]
    assert scores == sorted(scores, reverse=True)


def test_empty_input_is_handled():
    assert find_beacons([]) == []


def test_identical_timestamps_do_not_divide_by_zero():
    flows = make_flows([1000.0] * 20)
    assert find_beacons(flows, threshold=0.0) == []


def test_score_group_reports_every_component():
    flows = make_flows(beacon_starts(60.0, 40))
    beacon = score_group(SRC, DST, 443, 6, flows, window=flows[-1].end - flows[0].start)
    assert 0.0 <= beacon.interval_score <= 1.0
    assert 0.0 <= beacon.skew_score <= 1.0
    assert 0.0 <= beacon.size_score <= 1.0
    assert 0.0 <= beacon.coverage_score <= 1.0
    assert beacon.bytes_out == sum(f.bytes_out for f in flows)
    assert "every" in beacon.describe()
