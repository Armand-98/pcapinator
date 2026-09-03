"""Flow assembly tests.

Frames are built field by field from the constants in layers.types, which is
the contract this module is written against, and TCP flag combinations are
spelled out from RFC 9293 section 3.1 rather than as opaque integers.
"""

from __future__ import annotations

import pytest

from pcapinator.flows import FlowTable, assemble
from pcapinator.layers.types import (
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    Flow,
    FlowKey,
    Frame,
)

SYN = TCP_SYN
SYN_ACK = TCP_SYN | TCP_ACK
ACK = TCP_ACK
PSH_ACK = TCP_PSH | TCP_ACK
FIN_ACK = TCP_FIN | TCP_ACK
RST = TCP_RST
RST_ACK = TCP_RST | TCP_ACK

CLIENT = "10.0.0.5"
SERVER = "93.184.216.34"


def tcp(ts: float, src: str, sport: int, dst: str, dport: int, flags: int,
        payload: bytes = b"", wirelen: int | None = None, **kw) -> Frame:
    if wirelen is None:
        wirelen = 14 + 20 + 20 + len(payload)  # ethernet + IPv4 + TCP headers
    return Frame(ts=ts, src=src, dst=dst, proto=IPPROTO_TCP, sport=sport,
                 dport=dport, payload=payload, wirelen=wirelen, flags=flags,
                 **kw)


def udp(ts: float, src: str, sport: int, dst: str, dport: int,
        payload: bytes = b"", wirelen: int | None = None, **kw) -> Frame:
    if wirelen is None:
        wirelen = 14 + 20 + 8 + len(payload)
    return Frame(ts=ts, src=src, dst=dst, proto=IPPROTO_UDP, sport=sport,
                 dport=dport, payload=payload, wirelen=wirelen, **kw)


def handshake(ts: float, sport: int = 49152, dport: int = 443,
              step: float = 0.01) -> list[Frame]:
    return [
        tcp(ts, CLIENT, sport, SERVER, dport, SYN),
        tcp(ts + step, SERVER, dport, CLIENT, sport, SYN_ACK),
        tcp(ts + 2 * step, CLIENT, sport, SERVER, dport, ACK),
    ]


def teardown(ts: float, sport: int = 49152, dport: int = 443,
             step: float = 0.01) -> list[Frame]:
    """Graceful close: FIN, ACK of that FIN, FIN back, final ACK."""
    return [
        tcp(ts, CLIENT, sport, SERVER, dport, FIN_ACK),
        tcp(ts + step, SERVER, dport, CLIENT, sport, ACK),
        tcp(ts + 2 * step, SERVER, dport, CLIENT, sport, FIN_ACK),
        tcp(ts + 3 * step, CLIENT, sport, SERVER, dport, ACK),
    ]


def feed(table: FlowTable, frames) -> list[Flow]:
    out: list[Flow] = []
    for frame in frames:
        table.add(frame)
        out.extend(table.expire(frame.ts))
    return out


# --- one conversation, one flow --------------------------------------------

def test_both_directions_fold_into_one_flow():
    table = FlowTable()
    for frame in handshake(1000.0):
        table.add(frame)
    flows = table.close()

    assert len(flows) == 1
    flow = flows[0]
    assert flow.key == FlowKey(IPPROTO_TCP, CLIENT, 49152, SERVER, 443)
    assert flow.packets_out == 2
    assert flow.packets_in == 1
    assert flow.responded is True


def test_udp_request_and_reply_share_a_key():
    table = FlowTable()
    table.add(udp(5.0, CLIENT, 53124, "1.1.1.1", 53, b"\x00\x01query"))
    table.add(udp(5.2, "1.1.1.1", 53, CLIENT, 53124, b"\x00\x01answerbytes"))
    flow, = table.close()

    assert flow.key == FlowKey(IPPROTO_UDP, CLIENT, 53124, "1.1.1.1", 53)
    assert flow.packets_out == 1 and flow.packets_in == 1
    assert flow.payload_out == len(b"\x00\x01query")
    assert flow.payload_in == len(b"\x00\x01answerbytes")
    assert flow.responded is True


def test_unanswered_udp_never_marks_responded():
    table = FlowTable()
    table.add(udp(1.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    flow, = table.close()
    assert flow.responded is False
    assert flow.packets_in == 0 and flow.bytes_in == 0


def test_icmp_without_ports_still_pairs_both_directions():
    echo = Frame(ts=1.0, src=CLIENT, dst=SERVER, proto=IPPROTO_ICMP, sport=0,
                 dport=0, payload=b"\x08\x00" + b"\x00" * 30, wirelen=76)
    reply = Frame(ts=1.1, src=SERVER, dst=CLIENT, proto=IPPROTO_ICMP, sport=0,
                  dport=0, payload=b"\x00\x00" + b"\x00" * 30, wirelen=76)
    table = FlowTable()
    table.add(echo)
    table.add(reply)
    flow, = table.close()

    assert flow.key == FlowKey(IPPROTO_ICMP, CLIENT, 0, SERVER, 0)
    assert flow.packets == 2
    assert flow.responded is True


def test_distinct_source_ports_are_distinct_flows():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 40000, SERVER, 443, SYN))
    table.add(tcp(1.0, CLIENT, 40001, SERVER, 443, SYN))
    assert len(table) == 2


def test_same_ports_different_protocol_are_distinct_flows():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 5353, SERVER, 5353, SYN))
    table.add(udp(1.0, CLIENT, 5353, SERVER, 5353, b"x"))
    assert len(table) == 2
    assert {f.key.proto for f in table.close()} == {IPPROTO_TCP, IPPROTO_UDP}


# --- orientation ------------------------------------------------------------

def test_first_sender_is_initiator_without_a_syn():
    table = FlowTable()
    table.add(tcp(1.0, SERVER, 443, CLIENT, 49152, PSH_ACK, b"midstream"))
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, ACK))
    flow, = table.close()
    assert flow.key == FlowKey(IPPROTO_TCP, SERVER, 443, CLIENT, 49152)


def test_late_syn_corrects_orientation_and_swaps_counters():
    table = FlowTable()
    # Capture starts mid-conversation, so the server looks like the initiator.
    table.add(tcp(1.0, SERVER, 443, CLIENT, 49152, PSH_ACK, b"1234"))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, PSH_ACK, b"56"))
    table.add(tcp(2.0, CLIENT, 49152, SERVER, 443, SYN))
    flow, = table.close()

    assert flow.key == FlowKey(IPPROTO_TCP, CLIENT, 49152, SERVER, 443)
    assert flow.packets_out == 1          # the SYN, now outbound
    assert flow.packets_in == 2           # the server's two frames, swapped
    assert flow.payload_out == 0
    assert flow.payload_in == 6
    assert flow.bytes_in == 2 * 54 + 4 + 2
    assert flow.responded is True         # the responder had already spoken


def test_syn_ack_first_names_its_sender_the_responder():
    table = FlowTable()
    table.add(tcp(1.0, SERVER, 443, CLIENT, 49152, SYN_ACK))
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, ACK))
    flow, = table.close()

    assert flow.key == FlowKey(IPPROTO_TCP, CLIENT, 49152, SERVER, 443)
    assert flow.packets_out == 1 and flow.packets_in == 1
    assert flow.responded is True


def test_late_syn_ack_corrects_an_assumed_orientation():
    table = FlowTable()
    table.add(tcp(1.0, SERVER, 443, CLIENT, 49152, ACK))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, SYN_ACK))
    flow, = table.close()
    assert flow.key.src == CLIENT
    assert flow.packets_in == 2
    assert flow.packets_out == 0


def test_syn_confirming_the_assumed_orientation_leaves_counters_alone():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, ACK))
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, SYN))
    flow, = table.close()
    assert flow.key.src == CLIENT
    assert flow.packets_out == 2 and flow.packets_in == 0
    assert flow.responded is False


def test_syn_retransmission_does_not_open_a_second_flow():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(2.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(5.0, CLIENT, 49152, SERVER, 443, SYN))
    assert len(table) == 1
    flow, = table.close()
    assert flow.packets_out == 3


def test_server_syn_does_not_reorient_an_already_oriented_flow():
    """A SYN from the responder cannot flip a flow a SYN already oriented."""
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, SYN))  # simultaneous open
    flow, = table.close()
    assert flow.key.src == CLIENT
    assert flow.packets_out == 1 and flow.packets_in == 1


# --- accumulation -----------------------------------------------------------

def test_byte_and_payload_counters_are_per_direction():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, PSH_ACK, b"a" * 100,
                  wirelen=154))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, PSH_ACK, b"b" * 500,
                  wirelen=554))
    table.add(tcp(1.2, SERVER, 443, CLIENT, 49152, ACK, wirelen=54))
    flow, = table.close()

    assert (flow.payload_out, flow.payload_in) == (100, 500)
    assert (flow.bytes_out, flow.bytes_in) == (154, 554 + 54)
    assert flow.bytes == 154 + 554 + 54
    assert flow.packets == 3


def test_flags_seen_is_the_or_of_every_flag():
    table = FlowTable()
    for frame in handshake(1.0):
        table.add(frame)
    table.add(tcp(1.5, CLIENT, 49152, SERVER, 443, PSH_ACK, b"x"))
    for frame in teardown(2.0):
        table.add(frame)
    flow, = table.expire(2.03)

    assert flow.flags_seen == TCP_SYN | TCP_ACK | TCP_PSH | TCP_FIN
    assert not flow.flags_seen & TCP_RST


def test_timestamps_come_from_the_capture():
    # A capture replayed years after it was taken must report its own clock.
    base = 981_173_106.5
    table = FlowTable()
    table.add(tcp(base, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(base + 12.25, SERVER, 443, CLIENT, 49152, SYN_ACK))
    flow, = table.close()

    assert flow.start == base
    assert flow.end == base + 12.25
    assert flow.duration == pytest.approx(12.25)


def test_out_of_order_timestamps_keep_start_and_end_extremal():
    table = FlowTable()
    table.add(udp(100.0, CLIENT, 1234, SERVER, 53, b"a"))
    table.add(udp(90.0, SERVER, 53, CLIENT, 1234, b"b"))
    table.add(udp(110.0, CLIENT, 1234, SERVER, 53, b"c"))
    flow, = table.close()
    assert flow.start == 90.0
    assert flow.end == 110.0


# --- TCP connection lifecycle ----------------------------------------------

def test_rst_finishes_the_flow_before_any_timeout():
    table = FlowTable(tcp_timeout=300.0)
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 445, SYN))
    assert table.expire(1.0) == []
    table.add(tcp(1.1, SERVER, 445, CLIENT, 49152, RST_ACK))
    flows = table.expire(1.1)

    assert len(flows) == 1
    assert flows[0].flags_seen & TCP_RST
    assert len(table) == 0


def test_completed_teardown_finishes_the_flow_before_any_timeout():
    table = FlowTable(tcp_timeout=300.0)
    frames = handshake(1.0) + teardown(2.0)
    emitted = feed(table, frames)

    assert len(emitted) == 1
    assert len(table) == 0
    flow = emitted[0]
    assert flow.packets == len(frames)
    assert flow.end == 2.03


def test_one_sided_fin_does_not_finish_the_flow():
    table = FlowTable(tcp_timeout=300.0)
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, FIN_ACK))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, ACK))
    assert table.expire(100.0) == []
    assert len(table) == 1
    assert table.expire(400.0)[0].packets == 2


def test_teardown_missing_its_final_ack_waits_for_the_timeout():
    table = FlowTable(tcp_timeout=300.0)
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, FIN_ACK))
    table.add(tcp(1.1, SERVER, 443, CLIENT, 49152, FIN_ACK))
    assert table.expire(200.0) == []
    assert table.expire(400.0)[0].packets == 2


def test_packet_after_a_reset_starts_a_new_flow():
    table = FlowTable()
    first = handshake(1.0) + [tcp(1.5, SERVER, 443, CLIENT, 49152, RST)]
    second = handshake(2.0)
    emitted = feed(table, first + second)

    assert len(emitted) == 1
    assert emitted[0].start == 1.0
    live = table.close()
    assert len(live) == 1
    assert live[0].start == 2.0


def test_repeated_callbacks_on_one_tuple_are_separate_flows():
    """Beacon detection depends on this: one connection per callback."""
    frames = []
    for i in range(12):
        base = 100.0 + i * 60.0
        frames += handshake(base, sport=49152)
        frames.append(tcp(base + 0.05, CLIENT, 49152, SERVER, 443, PSH_ACK,
                          b"beacon"))
        frames += teardown(base + 0.1, sport=49152)

    flows = list(assemble(frames, tcp_timeout=300.0))

    assert len(flows) == 12
    assert {f.key for f in flows} == {FlowKey(IPPROTO_TCP, CLIENT, 49152,
                                              SERVER, 443)}
    starts = sorted(f.start for f in flows)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(gap == pytest.approx(60.0) for gap in gaps)
    assert all(f.payload_out == 6 for f in flows)


def test_syn_during_teardown_opens_a_new_flow():
    """The final ACK never arrives and the tuple is reused immediately."""
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, FIN_ACK))
    table.add(tcp(1.2, SERVER, 443, CLIENT, 49152, FIN_ACK))
    table.add(tcp(1.3, CLIENT, 49152, SERVER, 443, SYN))

    finished = table.expire(1.3)
    assert len(finished) == 1
    assert finished[0].packets == 3
    assert len(table) == 1
    assert table.close()[0].packets == 1


def test_data_after_a_completed_teardown_starts_a_new_flow():
    table = FlowTable()
    feed(table, handshake(1.0) + teardown(2.0))
    table.add(tcp(3.0, SERVER, 443, CLIENT, 49152, PSH_ACK, b"late"))
    live = table.close()
    assert len(live) == 1
    assert live[0].key.src == SERVER  # no SYN, so the sender is the initiator
    assert live[0].packets == 1


# --- expiry and timeouts ----------------------------------------------------

def test_idle_flow_expires_at_its_timeout_and_not_before():
    table = FlowTable(tcp_timeout=300.0)
    table.add(tcp(1000.0, CLIENT, 49152, SERVER, 443, SYN))
    assert table.expire(1299.9) == []
    assert len(table) == 1
    flows = table.expire(1300.0)
    assert len(flows) == 1 and len(table) == 0


def test_tcp_and_udp_use_their_own_timeouts():
    table = FlowTable(tcp_timeout=300.0, udp_timeout=60.0)
    table.add(tcp(0.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(udp(0.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))

    expired = table.expire(100.0)
    assert [f.key.proto for f in expired] == [IPPROTO_UDP]
    assert len(table) == 1
    assert [f.key.proto for f in table.expire(400.0)] == [IPPROTO_TCP]


def test_activity_refreshes_the_idle_timer():
    table = FlowTable(udp_timeout=60.0)
    table.add(udp(0.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    table.add(udp(50.0, "8.8.8.8", 53, CLIENT, 40000, b"a"))
    assert table.expire(100.0) == []
    assert table.expire(111.0)[0].packets == 2


def test_the_capture_clock_alone_drives_expiry():
    table = FlowTable(udp_timeout=60.0)
    table.add(udp(0.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    table.add(udp(200.0, CLIENT, 40001, "8.8.8.8", 53, b"q"))  # advances time
    assert table.ready == 1
    assert len(table) == 1
    assert table.expire(200.0)[0].key.sport == 40000


def test_a_flow_is_emitted_exactly_once():
    table = FlowTable(udp_timeout=10.0)
    table.add(udp(0.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    first = table.expire(100.0)
    assert len(first) == 1
    assert table.expire(200.0) == []
    assert table.close() == []


def test_close_drains_flows_however_recent():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(udp(1.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    flows = table.close()
    assert len(flows) == 2
    assert len(table) == 0
    assert table.close() == []


def test_backwards_clock_never_expires_a_live_flow():
    table = FlowTable(udp_timeout=60.0)
    table.add(udp(1000.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    assert table.expire(0.0) == []
    assert len(table) == 1


def test_rejects_nonsense_construction():
    with pytest.raises(ValueError):
        FlowTable(tcp_timeout=0.0)
    with pytest.raises(ValueError):
        FlowTable(udp_timeout=-1.0)
    with pytest.raises(ValueError):
        FlowTable(max_flows=0)


# --- fragments --------------------------------------------------------------

def test_fragments_key_on_addresses_with_zero_ports():
    table = FlowTable()
    first = udp(1.0, CLIENT, 40000, SERVER, 4444, b"\x00" * 1400,
                fragmented=True)
    rest = Frame(ts=1.01, src=CLIENT, dst=SERVER, proto=IPPROTO_UDP, sport=0,
                 dport=0, payload=b"\x00" * 600, wirelen=634, fragmented=True)
    back = Frame(ts=1.02, src=SERVER, dst=CLIENT, proto=IPPROTO_UDP, sport=0,
                 dport=0, payload=b"\x00" * 600, wirelen=634, fragmented=True)
    for frame in (first, rest, back):
        table.add(frame)
    flow, = table.close()

    assert flow.key == FlowKey(IPPROTO_UDP, CLIENT, 0, SERVER, 0)
    assert flow.packets_out == 2 and flow.packets_in == 1
    assert flow.payload_out == 2000


def test_fragments_do_not_merge_into_the_ported_flow():
    table = FlowTable()
    table.add(udp(1.0, CLIENT, 40000, SERVER, 4444, b"x"))
    table.add(udp(1.1, CLIENT, 40000, SERVER, 4444, b"y", fragmented=True))
    assert len(table) == 2
    assert {f.key.dport for f in table.close()} == {0, 4444}


# --- memory bound -----------------------------------------------------------

def test_table_stays_small_across_many_short_lived_flows():
    table = FlowTable(tcp_timeout=30.0, udp_timeout=5.0)
    collected = 0
    peak = 0
    for i in range(20_000):
        ts = i * 1.0
        port = 1024 + (i % 60000)
        table.add(udp(ts, CLIENT, port, "8.8.8.8", 53, b"q" * 20))
        table.add(udp(ts + 0.1, "8.8.8.8", 53, CLIENT, port, b"a" * 40))
        collected += len(table.expire(ts + 0.1))
        peak = max(peak, len(table))

    assert peak <= 8
    collected += len(table.close())
    assert collected == 20_000


def test_half_open_scan_does_not_grow_the_table_without_bound():
    """A SYN flood with unique ports has no idle time to exploit."""
    table = FlowTable(tcp_timeout=300.0, max_flows=1000)
    for i in range(20_000):
        table.add(tcp(i * 0.0001, "203.0.113.9", 1024 + i % 60000,
                      CLIENT, 22, SYN))
        assert len(table) <= 1000
    evicted = table.expire(2.0)
    assert len(evicted) == 19_000
    assert all(f.responded is False for f in evicted)
    assert all(f.flags_seen == TCP_SYN for f in evicted)


def test_eviction_prefers_the_least_recently_active_flow():
    table = FlowTable(tcp_timeout=1e9, udp_timeout=1e9, max_flows=2)
    table.add(udp(1.0, CLIENT, 1, SERVER, 53, b"a"))
    table.add(udp(2.0, CLIENT, 2, SERVER, 53, b"b"))
    table.add(udp(3.0, CLIENT, 1, SERVER, 53, b"c"))   # refreshes port 1
    table.add(udp(4.0, CLIENT, 3, SERVER, 53, b"d"))   # forces an eviction

    evicted = table.expire(4.0)
    assert [f.key.sport for f in evicted] == [2]
    assert sorted(f.key.sport for f in table.close()) == [1, 3]


def test_eviction_picks_the_older_front_across_protocols():
    table = FlowTable(tcp_timeout=1e9, udp_timeout=1e9, max_flows=2)
    table.add(udp(1.0, CLIENT, 1, SERVER, 53, b"a"))
    table.add(tcp(2.0, CLIENT, 2, SERVER, 443, SYN))
    table.add(tcp(3.0, CLIENT, 3, SERVER, 443, SYN))
    evicted = table.expire(3.0)
    assert [f.key.proto for f in evicted] == [IPPROTO_UDP]


def test_no_packet_payload_is_retained():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, PSH_ACK, b"secret" * 100))
    flow, = table.close()
    assert flow.payload_out == 600
    assert not any(isinstance(v, (bytes, bytearray))
                   for v in (getattr(flow, f) for f in flow.__slots__))


# --- hostile and degenerate input -------------------------------------------

def test_every_flag_set_at_once_finishes_the_flow_without_wedging():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, 0xFF, b"junk"))
    flows = table.expire(1.0)
    assert len(flows) == 1          # RST wins over the FIN and SYN bits
    assert len(table) == 0
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, ACK))
    assert len(table) == 1


def test_flow_to_self_is_handled():
    table = FlowTable()
    table.add(tcp(1.0, "127.0.0.1", 5000, "127.0.0.1", 5000, SYN))
    table.add(tcp(1.1, "127.0.0.1", 5000, "127.0.0.1", 5000, ACK))
    flow, = table.close()
    assert flow.packets == 2
    assert flow.key.src == flow.key.dst


def test_empty_input_yields_nothing():
    assert list(assemble([])) == []
    assert FlowTable().close() == []


def test_ipv6_addresses_key_normally():
    a, b = "2001:db8::1", "2001:db8::2"
    table = FlowTable()
    table.add(Frame(ts=1.0, src=a, dst=b, proto=IPPROTO_TCP, sport=1234,
                    dport=80, payload=b"", wirelen=74, flags=SYN,
                    ip_version=6))
    table.add(Frame(ts=1.1, src=b, dst=a, proto=IPPROTO_TCP, sport=80,
                    dport=1234, payload=b"", wirelen=74, flags=SYN_ACK,
                    ip_version=6))
    flow, = table.close()
    assert flow.key == FlowKey(IPPROTO_TCP, a, 1234, b, 80)
    assert flow.responded is True


def test_truncated_frames_count_wire_length_not_captured_bytes():
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, PSH_ACK, b"only-a-snippet",
                  wirelen=1514, truncated=True))
    flow, = table.close()
    assert flow.bytes_out == 1514
    assert flow.payload_out == len(b"only-a-snippet")


# --- assemble ---------------------------------------------------------------

def test_assemble_streams_finished_flows_and_drains_at_the_end():
    frames = (handshake(1.0, sport=1111) +
              [tcp(1.5, SERVER, 443, CLIENT, 1111, RST)] +
              handshake(10.0, sport=2222) +
              handshake(3000.0, sport=3333))
    flows = list(assemble(frames, tcp_timeout=300.0))

    assert [f.key.sport for f in flows] == [1111, 2222, 3333]
    assert flows[0].flags_seen & TCP_RST
    assert flows[1].duration == pytest.approx(0.02)


def test_assemble_is_lazy():
    def frames():
        yield tcp(1.0, CLIENT, 49152, SERVER, 443, SYN)
        yield tcp(1.1, SERVER, 443, CLIENT, 49152, RST)
        raise AssertionError("consumed past the first finished flow")

    stream = assemble(frames())
    flow = next(stream)
    assert flow.flags_seen & TCP_RST


# --- idle expiry when the flow's own packets advance the clock --------------

def test_idle_gap_on_one_tuple_splits_the_flow():
    """The packet that proves the gap belongs to the NEW flow, not the old one.

    Nothing else has to be in the capture for the idle timeout to fire.
    """
    table = FlowTable(udp_timeout=60.0)
    table.add(udp(0.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    table.add(udp(1000.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))

    old = table.expire(1000.0)
    assert [(f.start, f.end, f.packets) for f in old] == [(0.0, 0.0, 1)]
    assert [(f.start, f.packets) for f in table.close()] == [(1000.0, 1)]


def test_tcp_idle_gap_on_one_tuple_splits_the_flow():
    table = FlowTable(tcp_timeout=300.0)
    table.add(tcp(0.0, CLIENT, 49152, SERVER, 443, ACK))
    table.add(tcp(400.0, CLIENT, 49152, SERVER, 443, ACK))
    assert [f.packets for f in table.expire(400.0)] == [1]
    assert [f.packets for f in table.close()] == [1]


def test_icmp_beacon_on_one_pair_is_many_flows_not_one():
    """An ICMP tunnel keys on the address pair alone, so it is the case where
    only the beacon's own packets ever advance the capture clock."""
    frames = [Frame(ts=i * 300.0, src=CLIENT, dst=SERVER, proto=IPPROTO_ICMP,
                    sport=0, dport=0, payload=b"x" * 32, wirelen=74)
              for i in range(20)]
    flows = list(assemble(frames, udp_timeout=60.0))

    assert len(flows) == 20
    assert all(f.packets == 1 for f in flows)
    assert sorted(f.start for f in flows) == [i * 300.0 for i in range(20)]


def test_a_flow_kept_alive_within_its_timeout_is_never_split():
    table = FlowTable(udp_timeout=60.0)
    for i in range(10):
        table.add(udp(i * 50.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
    assert table.expire(450.0) == []
    flow, = table.close()
    assert flow.packets == 10 and flow.start == 0.0 and flow.end == 450.0


def test_idle_split_holds_the_table_flat_on_one_long_lived_tuple():
    table = FlowTable(udp_timeout=60.0)
    for i in range(5000):
        table.add(udp(i * 100.0, CLIENT, 40000, "8.8.8.8", 53, b"q"))
        assert len(table) == 1
        assert table.ready <= 1
        table.expire(i * 100.0)


# --- tuple reuse after a half-closed connection ----------------------------

def test_syn_after_a_one_sided_fin_opens_a_new_flow():
    """The responder's FIN was lost by the sensor; the tuple is reused anyway.

    Merging the two connections would erase the callback interval a beacon is
    detected by.
    """
    table = FlowTable(tcp_timeout=300.0)
    for frame in handshake(1.0):
        table.add(frame)
    table.add(tcp(1.5, CLIENT, 49152, SERVER, 443, FIN_ACK))
    table.add(tcp(60.0, CLIENT, 49152, SERVER, 443, SYN))

    finished = table.expire(60.0)
    assert [f.packets for f in finished] == [4]
    assert [(f.start, f.packets) for f in table.close()] == [(60.0, 1)]


def test_syn_ack_reusing_a_tuple_in_teardown_opens_a_new_flow():
    """The client SYN was not captured, so the reuse shows up as a SYN-ACK."""
    table = FlowTable()
    table.add(tcp(1.0, CLIENT, 49152, SERVER, 443, SYN))
    table.add(tcp(1.1, CLIENT, 49152, SERVER, 443, FIN_ACK))
    table.add(tcp(1.2, SERVER, 443, CLIENT, 49152, FIN_ACK))
    table.add(tcp(1.3, SERVER, 443, CLIENT, 49152, SYN_ACK))

    assert [f.packets for f in table.expire(1.3)] == [3]
    new, = table.close()
    assert new.packets == 1
    assert new.key == FlowKey(IPPROTO_TCP, CLIENT, 49152, SERVER, 443)
    assert new.responded is True
