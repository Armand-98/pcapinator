"""DNS tunneling detector tests.

Traffic is synthesised with known ground truth: encoded channels the detector
must find, and high cardinality benign traffic it must leave alone. The benign
cases are the point of this file. Every generator is seeded, so a failure is
always reproducible.
"""

import random
import string

import pytest

from pcapinator.detect.dnstunnel import find_tunnels
from pcapinator.dnsview import DnsEvent
from pcapinator.layers.dns import (QTYPE_A, QTYPE_CNAME, QTYPE_NULL, QTYPE_TXT,
                                   RCODE_NXDOMAIN)

CLIENT = "10.0.0.42"
SERVER = "10.0.0.1"

B32 = "abcdefghijklmnopqrstuvwxyz234567"
HEX = "0123456789abcdef"


def encode(rng, alphabet, length):
    return "".join(rng.choice(alphabet) for _ in range(length))


def query(name, ts, *, qtype=QTYPE_A, client=CLIENT):
    return DnsEvent(ts=ts, client=client, server=SERVER, name=name,
                    qtype=qtype, rcode=0, is_response=False)


def answer(name, ts, *, qtype=QTYPE_A, rcode=0, client=CLIENT):
    return DnsEvent(ts=ts, client=client, server=SERVER, name=name,
                    qtype=qtype, rcode=rcode, is_response=True)


def conversation(names, *, qtype=QTYPE_A, rcode=0, start=1000.0, gap=1.0,
                 client=CLIENT, respond=True):
    """Interleave queries and their answers, as a capture of both directions."""
    events = []
    for index, name in enumerate(names):
        ts = start + index * gap
        events.append(query(name, ts, qtype=qtype, client=client))
        if respond:
            events.append(answer(name, ts + 0.01, qtype=qtype, rcode=rcode,
                                 client=client))
    return events


# --- traffic generators ----------------------------------------------------

def tunnel_names(count, *, seed, parent="t.tun-c2.net", chunks=(50, 40)):
    """iodine style: one fresh base32 encoded message per query."""
    rng = random.Random(seed)
    return [".".join(encode(rng, B32, size) for size in chunks) + "." + parent
            for _ in range(count)]


def cdn_names(count, *, seed, parent="cloudfront.net", length=16):
    """A distinct hashed hostname per object, which is what a CDN looks like."""
    rng = random.Random(seed)
    return [f"d{encode(rng, HEX, length)}.{parent}" for _ in range(count)]


def guid_names(count, *, seed):
    """Azure style: a GUID plus fixed service labels, four labels deep."""
    rng = random.Random(seed)
    names = []
    for _ in range(count):
        parts = [encode(rng, HEX, size) for size in (8, 4, 4, 4, 12)]
        names.append("-".join(parts) + ".blob.core.windows.net")
    return names


def rdns_names(count, *, seed):
    rng = random.Random(seed)
    return [f"{rng.randrange(256)}.{rng.randrange(256)}.168.192.in-addr.arpa"
            for _ in range(count)]


def dga_names(count, *, seed, parent=None):
    """One query per generated domain, which is the DGA detector's problem."""
    rng = random.Random(seed)
    names = []
    for _ in range(count):
        label = encode(rng, string.ascii_lowercase, rng.randrange(9, 14))
        names.append(f"{label}.{parent}" if parent else f"{label}.com")
    return names


def hash_lookup_names(count, *, seed, length=40):
    """Antivirus reputation lookups: one file hash encoded per query."""
    rng = random.Random(seed)
    return [f"{encode(rng, HEX, length)}.hash.av-vendor.net"
            for _ in range(count)]


def browsing_names(count, *, seed):
    """A handful of real hostnames, revisited, which is what users generate."""
    rng = random.Random(seed)
    hosts = ["www", "api", "static", "images", "login", "cdn", "mail",
             "checkout", "analytics", "assets"]
    return [f"{rng.choice(hosts)}.corp.example.com" for _ in range(count)]


def long_hostname_names(count, *, seed):
    """Long, structured, low entropy service names, revisited."""
    rng = random.Random(seed)
    hosts = ["prod-api-gateway-eu-west-1-internal",
             "staging-payment-processor-us-east-2-internal",
             "prod-message-queue-broker-ap-south-1-internal"]
    return [f"{rng.choice(hosts)}.svc.corp.example.com" for _ in range(count)]


def scored(events, parent):
    """Every scored domain, ignoring the threshold, for margin assertions."""
    for tunnel in find_tunnels(events, threshold=0.0):
        if tunnel.parent == parent:
            return tunnel
    return None


def only(tunnels):
    assert len(tunnels) == 1, f"expected exactly one tunnel, got {tunnels}"
    return tunnels[0]


# --- detection -------------------------------------------------------------

def test_base32_tunnel_is_detected():
    names = tunnel_names(300, seed=1)
    tunnel = only(find_tunnels(conversation(names, qtype=QTYPE_NULL, gap=0.4)))
    assert tunnel.parent == "tun-c2.net"
    assert tunnel.client == CLIENT
    assert tunnel.queries == 300
    assert tunnel.unique_subdomains == 300
    assert tunnel.score > 0.85


def test_tunnel_evidence_is_actionable():
    names = tunnel_names(200, seed=2)
    tunnel = only(find_tunnels(conversation(names, qtype=QTYPE_TXT, gap=0.5)))
    assert len(tunnel.samples) == 5
    assert all(sample in names for sample in tunnel.samples)
    # 90 base32 characters is 450 bits, so ~56 bytes of payload per query.
    assert 8000 < tunnel.upload_bytes < 16000
    assert tunnel.data_queries == 200
    assert tunnel.qtype_score == 1.0
    assert tunnel.name_len == pytest.approx(90.0)
    assert tunnel.entropy > 4.5


def test_fixed_tunnel_prefix_is_not_counted_as_payload():
    """The constant routing label must be stripped before scoring length."""
    names = tunnel_names(120, seed=3, parent="gateway.tun-c2.net")
    tunnel = only(find_tunnels(conversation(names, qtype=QTYPE_NULL, gap=0.5)))
    assert tunnel.name_len == pytest.approx(90.0)


def test_slow_hex_exfiltration_over_a_records_is_detected():
    """No TXT skew, no rate: capacity alone has to carry the verdict."""
    rng = random.Random(4)
    names = [f"{encode(rng, HEX, 63)}.x.exfil-node.org" for _ in range(60)]
    tunnel = only(find_tunnels(conversation(names, gap=10.0,
                                            rcode=RCODE_NXDOMAIN)))
    assert tunnel.nxdomain == 60
    assert tunnel.nxdomain_score == 1.0
    assert tunnel.rate_score < 0.05
    assert tunnel.score > 0.7


def test_cname_tunnel_counts_as_data_carrying():
    names = tunnel_names(80, seed=5, chunks=(60, 60))
    tunnel = only(find_tunnels(conversation(names, qtype=QTYPE_CNAME)))
    assert tunnel.data_queries == 80


def test_query_only_capture_does_not_assume_answers_succeeded():
    names = tunnel_names(120, seed=6)
    events = [query(name, 1000.0 + i * 0.5, qtype=QTYPE_NULL)
              for i, name in enumerate(names)]
    tunnel = only(find_tunnels(events))
    assert tunnel.responses == 0
    assert tunnel.nxdomain_score == 0.0
    assert tunnel.score > 0.85


def test_results_are_sorted_worst_first():
    loud = conversation(tunnel_names(300, seed=7, parent="t.loud-c2.net"),
                        qtype=QTYPE_NULL, gap=0.2)
    quiet = conversation(tunnel_names(40, seed=8, parent="t.quiet-c2.net",
                                      chunks=(30, 20)),
                         qtype=QTYPE_A, gap=30.0)
    tunnels = find_tunnels(loud + quiet, threshold=0.0)
    scores = [t.score for t in tunnels]
    assert scores == sorted(scores, reverse=True)
    assert tunnels[0].parent == "loud-c2.net"


def test_busiest_client_is_reported():
    names = tunnel_names(100, seed=9)
    events = conversation(names[:70], qtype=QTYPE_NULL)
    events += conversation(names[70:], qtype=QTYPE_NULL, client="10.0.0.99",
                           start=2000.0)
    tunnel = only(find_tunnels(events))
    assert tunnel.client == CLIENT
    assert tunnel.clients == 2


# --- false positives -------------------------------------------------------

def test_cdn_hashed_hostnames_are_not_tunnels():
    """Maximal cardinality, normal length, small alphabet: not payload.

    800 unique hostnames, one per query, is a higher cardinality than most real
    tunnels reach. A 16 character hex label is rejected on entropy before any
    of that is even scored.
    """
    events = conversation(cdn_names(800, seed=11), gap=0.05)
    assert find_tunnels(events, threshold=0.0) == []


def test_cdn_cardinality_alone_is_not_evidence():
    events = conversation(cdn_names(600, seed=12, parent="akamaiedge.net",
                                    length=28), gap=0.05)
    tunnel = scored(events, "akamaiedge.net")
    assert tunnel.cardinality_score == 1.0
    assert tunnel.score < 0.2


def test_long_cdn_hostnames_are_not_tunnels():
    events = conversation(cdn_names(600, seed=12, parent="akamaiedge.net",
                                    length=28), gap=0.05)
    assert find_tunnels(events) == []
    assert scored(events, "akamaiedge.net").score < 0.5


def test_cloud_storage_guid_hostnames_are_not_tunnels():
    events = conversation(guid_names(500, seed=13), gap=0.1)
    assert find_tunnels(events) == []
    tunnel = scored(events, "windows.net")
    # The fixed service labels are routing, not payload.
    assert tunnel.name_len == pytest.approx(36.0)
    assert tunnel.score < 0.5


def test_reverse_dns_sweep_is_not_a_tunnel():
    events = conversation(rdns_names(2000, seed=14), gap=0.01)
    assert find_tunnels(events, threshold=0.0) == []


def test_dga_traffic_is_left_to_the_dga_detector():
    """One query per registered domain never accumulates under a parent."""
    events = conversation(dga_names(400, seed=15), gap=0.5,
                          rcode=RCODE_NXDOMAIN)
    assert find_tunnels(events, threshold=0.0) == []


def test_dga_under_a_shared_dynamic_dns_parent_is_not_a_tunnel():
    """Same parent for every query, high entropy, but nothing fits in a label."""
    events = conversation(dga_names(400, seed=16, parent="ddns.net"), gap=0.5,
                          rcode=RCODE_NXDOMAIN)
    assert find_tunnels(events) == []
    assert scored(events, "ddns.net") is None or scored(events, "ddns.net").score < 0.2


def test_sha256_reputation_lookups_are_a_known_false_positive():
    """Documented limitation, asserted so it cannot regress silently.

    64 hex characters is ~245 bits per query, the same capacity as a real
    tunnel. Nothing in the traffic separates the two; only an allowlist does.
    """
    events = conversation(hash_lookup_names(200, seed=33, length=64),
                          qtype=QTYPE_TXT, gap=3.0, rcode=RCODE_NXDOMAIN)
    assert only(find_tunnels(events)).parent == "av-vendor.net"


def test_antivirus_hash_lookups_are_not_tunnels():
    """SHA-1 per query over TXT, mostly NXDOMAIN: the hardest benign case."""
    names = hash_lookup_names(200, seed=17)
    events = conversation(names[:120], qtype=QTYPE_TXT, gap=3.0,
                          rcode=RCODE_NXDOMAIN)
    events += conversation(names[120:], qtype=QTYPE_TXT, gap=3.0, start=1400.0)
    assert find_tunnels(events) == []
    tunnel = scored(events, "av-vendor.net")
    assert tunnel.qtype_score == 1.0 and tunnel.nxdomain_score > 0.5
    assert tunnel.score < 0.55


def test_md5_reputation_lookups_are_not_tunnels():
    events = conversation(hash_lookup_names(300, seed=18, length=32),
                          qtype=QTYPE_TXT, gap=1.0, rcode=RCODE_NXDOMAIN)
    assert find_tunnels(events) == []
    assert scored(events, "av-vendor.net").score < 0.45


def test_ordinary_browsing_is_not_a_tunnel():
    events = conversation(browsing_names(500, seed=19), gap=0.3)
    assert find_tunnels(events, threshold=0.0) == []


def test_long_low_entropy_hostnames_are_not_tunnels():
    events = conversation(long_hostname_names(400, seed=20), gap=0.3)
    assert find_tunnels(events, threshold=0.0) == []


def test_tunnel_is_found_among_benign_traffic():
    events = conversation(cdn_names(800, seed=21), gap=0.05)
    events += conversation(guid_names(300, seed=22), gap=0.2, start=1000.0)
    events += conversation(rdns_names(500, seed=23), gap=0.02, start=1000.0)
    events += conversation(browsing_names(600, seed=24), gap=0.2, start=1000.0)
    events += conversation(hash_lookup_names(200, seed=25), qtype=QTYPE_TXT,
                           gap=2.0, start=1000.0, rcode=RCODE_NXDOMAIN)
    events += conversation(dga_names(300, seed=26), gap=1.0, start=1000.0,
                           rcode=RCODE_NXDOMAIN)
    events += conversation(tunnel_names(250, seed=27), qtype=QTYPE_NULL,
                           gap=0.5, start=1000.0)
    tunnel = only(find_tunnels(events))
    assert tunnel.parent == "tun-c2.net"


# --- gates and robustness --------------------------------------------------

def test_a_handful_of_queries_is_never_enough():
    events = conversation(tunnel_names(11, seed=28), qtype=QTYPE_NULL)
    assert find_tunnels(events, threshold=0.0) == []


def test_repeated_identical_encoded_name_is_not_a_tunnel():
    """A cached long name queried again and again carries no new data."""
    name = tunnel_names(1, seed=29)[0]
    events = conversation([name] * 200, qtype=QTYPE_NULL, gap=0.5)
    assert find_tunnels(events, threshold=0.0) == []


def test_apex_and_two_label_queries_are_ignored():
    events = conversation(["tun-c2.net"] * 50, qtype=QTYPE_NULL)
    assert find_tunnels(events, threshold=0.0) == []


def test_empty_input():
    assert find_tunnels([]) == []


def test_malformed_names_do_not_raise():
    rng = random.Random(30)
    weird = ["", ".", "..", "a..b", "-", "x" * 300,
             "\x00\xff.\x01.evil.test", "ünïcödé.host.example.com",
             ".".join("q" for _ in range(200)) + ".deep.test",
             ".".join(str(rng.randrange(10)) for _ in range(60))]
    events = [query(name, 1000.0 + i * 0.1)
              for i in range(30) for name in weird]
    find_tunnels(events, threshold=0.0)


def test_zero_span_burst_does_not_divide_by_zero():
    names = tunnel_names(50, seed=31)
    events = [query(name, 1000.0, qtype=QTYPE_NULL) for name in names]
    tunnel = only(find_tunnels(events))
    assert tunnel.rate_score == 1.0
    assert tunnel.sustain_score == 0.0


def test_large_capture_is_bounded_and_deterministic():
    events = conversation(tunnel_names(5000, seed=32), qtype=QTYPE_NULL,
                          gap=0.05)
    first = find_tunnels(events)
    second = find_tunnels(events)
    assert first == second
    assert only(first).queries == 5000
