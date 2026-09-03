"""DNS view tests: what the detectors actually see of a capture."""

import struct

import pytest

from pcapinator.dnsview import DnsEvent, dns_events
from pcapinator.layers.types import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, Frame

CLIENT = "10.0.0.5"
RESOLVER = "10.0.0.1"


def qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_message(name, *, qtype=1, response=False, rcode=0, txid=0x1234):
    flags = (0x8180 | rcode) if response else 0x0100
    return (struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
            + qname(name) + struct.pack("!HH", qtype, 1))


def frame(payload, *, proto=IPPROTO_UDP, src=CLIENT, dst=RESOLVER,
          sport=53000, dport=53, ts=1000.0):
    return Frame(ts=ts, src=src, dst=dst, proto=proto, sport=sport, dport=dport,
                 payload=payload, wirelen=len(payload) + 42)


def query_frame(name, **kw):
    return frame(dns_message(name, **{k: v for k, v in kw.items()
                                      if k in ("qtype", "response", "rcode")}),
                 **{k: v for k, v in kw.items()
                    if k not in ("qtype", "response", "rcode")})


def test_a_query_yields_one_event():
    (event,) = list(dns_events([query_frame("www.example.com")]))
    assert event.name == "www.example.com"
    assert event.client == CLIENT
    assert event.server == RESOLVER
    assert event.qtype == 1
    assert not event.is_response
    assert event.ts == 1000.0


def test_a_response_attributes_the_client_correctly():
    """On the way back the addresses are reversed, but the client is still the
    client. Grouping by client is meaningless otherwise."""
    payload = dns_message("www.example.com", response=True, rcode=3)
    reply = frame(payload, src=RESOLVER, dst=CLIENT, sport=53, dport=53000)
    (event,) = list(dns_events([reply]))
    assert event.client == CLIENT
    assert event.server == RESOLVER
    assert event.is_response
    assert event.rcode == 3


def test_tcp_dns_is_read_through_its_length_prefix():
    body = dns_message("tcp.example.com")
    payload = struct.pack("!H", len(body)) + body
    (event,) = list(dns_events([frame(payload, proto=IPPROTO_TCP)]))
    assert event.name == "tcp.example.com"


def test_mdns_port_is_included():
    (event,) = list(dns_events([query_frame("printer.local", sport=5353, dport=5353)]))
    assert event.name == "printer.local"


def test_traffic_off_the_dns_ports_is_ignored():
    """A DNS-shaped payload on port 443 is not DNS activity. Without the port
    check the tunneling detector would score arbitrary encrypted traffic."""
    assert list(dns_events([query_frame("www.example.com", sport=51000, dport=443)])) == []


def test_non_transport_protocols_are_ignored():
    assert list(dns_events([frame(b"\x08\x00abcd", proto=IPPROTO_ICMP,
                                  sport=0, dport=0)])) == []


@pytest.mark.parametrize("payload", [
    b"",
    b"\x00",
    b"\xff" * 12,
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",   # header promises a question, none follows
    b"\x12\x34\x01\x00\xff\xff\x00\x00\x00\x00\x00\x00",   # 65535 questions claimed
])
def test_malformed_payloads_are_skipped_without_raising(payload):
    assert list(dns_events([frame(payload)])) == []


def test_a_bad_frame_does_not_stop_the_stream():
    frames = [frame(b"\xff" * 8), query_frame("good.example.com")]
    assert [e.name for e in dns_events(frames)] == ["good.example.com"]


def test_empty_input():
    assert list(dns_events([])) == []


# --- the view the detectors group on ---------------------------------------

def test_labels_drop_the_root():
    event = DnsEvent(1.0, CLIENT, RESOLVER, "a.b.example.com", 1, 0, False)
    assert event.labels == ["a", "b", "example", "com"]


def test_parent_collects_a_tunnels_traffic_together():
    """Tunnels vary the leftmost labels and keep the suffix fixed, so the last
    two labels are what gathers one tunnel's queries into one group."""
    names = ["MFRGG.tun.evil.com", "MZXW6.tun.evil.com", "NBSWY.tun.evil.com"]
    parents = {DnsEvent(1.0, CLIENT, RESOLVER, n, 16, 0, False).parent for n in names}
    assert parents == {"evil.com"}


def test_parent_of_a_bare_name_is_the_name():
    assert DnsEvent(1.0, CLIENT, RESOLVER, "localhost", 1, 0, False).parent == "localhost"


def test_labels_are_a_view_not_wire_truth():
    """A label may contain a literal dot byte, so splitting on dots cannot
    recover the original wire labels. Detectors must not assume it does."""
    event = DnsEvent(1.0, CLIENT, RESOLVER, "we.ird.example.com", 1, 0, False)
    assert event.labels == ["we", "ird", "example", "com"]
