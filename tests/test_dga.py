"""DGA detector tests.

The labelled set is built in this file so the measured numbers are reproducible:
real domains people actually resolve on one side, seeded generators in the style
of published DGA families on the other. Every generator is seeded, so a failure
is always reproducible.

The false positive rate is the assertion that matters. A detector that fires on
ordinary browsing is useless, so the benign set is deliberately stacked with the
hard cases: consonant-heavy real names (npmjs, xkcd, wsj), non-English brands,
short names, and names carrying digits.

Browsing history is not what a capture is made of, so BENIGN is not enough.
REAL_INFRA is the traffic an enterprise sensor actually sees - connectivity
checks, CDN and ad-tech shorthand, nameserver zones, IoT back ends - and it is
full of short consonant stacks that are indistinguishable from generated names
under a bigram model. HOLDOUT_BENIGN was never consulted while choosing a weight
or a ramp, so a zero there is evidence of separation rather than of fitting.

Measured over all 558 benign names: no false positives, worst benign 0.49
against a 0.55 threshold, recall 0.70, accuracy 0.92.
"""

import importlib.util
import math
import random
import string
from pathlib import Path

import pytest

from pcapinator.detect.bigrams import (ALPHABET, INDEX,
                                       LETTER_LOG_PROB, LOG_PROB)
from pcapinator.detect.dga import (CORRELATED_WEIGHTS, DEFAULT_THRESHOLD,
                                   DgaScore, find_dga, registrable,
                                   score_domain)
from pcapinator.dnsview import DnsEvent

SEED = 20240517
CLIENT = "10.0.0.5"
RESOLVER = "10.0.0.1"

BENIGN = """google facebook wikipedia cloudflare github stackoverflow nytimes amazon
youtube microsoft twitter reddit netflix instagram linkedin dropbox wordpress apple
yahoo baidu spotify gmail outlook adobe salesforce zoom slack shopify paypal ebay
espn imgur tumblr pinterest quora medium notion figma stripe twilio digitalocean
akamai fastly cloudfront googleapis gstatic doubleclick office365 live365 arxiv
ubuntu debian archlinux mozilla wireshark virustotal shodan crowdstrike splunk
elastic grafana datadog sentry atlassian bitbucket gitlab npmjs docker kubernetes
redis postgresql mysql sqlite nginx apache openssl letsencrypt duckduckgo
protonmail telegram whatsapp discord twitch roblox minecraft nintendo playstation
craigslist etsy walmart target costco chase wellsfargo schwab fidelity vanguard
robinhood coinbase okta zendesk hubspot mailchimp sendgrid cloudinary vercel
netlify heroku fastmail yandex vkontakte aliexpress taobao rakuten mercadolibre
seznam allegro zalando wetransfer bytedance tencent xiaomi huawei bilibili
lemonde spiegel repubblica lefigaro kinopoisk sberbank wildberries""".split()

# Short names carry almost no signal, which makes them the hard case: several of
# these are as improbable under the model as anything a generator emits.
SHORT_BENIGN = """bit ly xkcd ietf nmap pypi wsj npr pbs ibm att usps irs fbi mit
ucla nyu ups dhl fedex cnn bbc gmx ndtv nhk qq vk jd tv ok hh s3 web2 3m x1 o2
b2b mp3 utf8 ipv6 log4j sha256 base64 route53 7eleven w3schools""".split()

# Wordlist DGAs chain dictionary words. They are English by construction, so
# this method cannot see them; the assertion below pins that as a known gap
# rather than pretending otherwise.
WORDLIST_DGA = ["farmerpaper", "silverwinter", "coldmountain", "brokenletter",
                "summerbottle", "yellowmarket", "quietgardenlight"]

# Names an enterprise capture is full of and a browsing-history benign set is
# not: connectivity checks, CDN and ad-tech shorthand, nameserver zones, IoT
# back ends. They are consonant stacks, which is exactly what a DGA emits, so
# they are the false positive class that decides whether this is deployable.
REAL_INFRA = """msftncsi msftconnecttest lgtvsdp smtcdns jwpcdn nflxvideo nflximg
nflxso mktdcdn tvrmsn grvcdn zbjimg adsrvr hdfcbank crwdcntrl fbcdn dwcdn wjcdn
rlcdn krxd llnwd nstld ggpht ytimg akadns edgekey edgesuite bkrtx hdslb wsdvs
vdcdn qhimg symcb symcd atdmt cctv sncf iqiyi youku snssdk wscdns ksyuncdn
cvshealth zoomgov tiqcdn jsdelivr nordvpn expressvpn wsglb0 vscode-cdn bdstatic
sinaimg alicdn pstatp bytecdn sohucs cnzz serving-sys casalemedia pubmatic
rubiconproject 33across 3lift sovrn yieldmo taboola outbrain hsforms hsappstatic
onetrust trustarc wnsc wcpo kcra wsoc wxyz kmov wusa9 knbc wnbc kabc wjla whdh
wgn9 espncdn walgreens riteaid kroger albertsons gls-group trenitalia renfe
dominos icicibank axisbank kotak paytm phonepe npci bhimupi airtel vodafone
bouygtel swisscom proximus freenet strato hetzner scaleway contabo nfoservers
softlayer globalsign sectigo entrust thawte geotrust sfdcstatic visualforce
atl-paas githubusercontent githubassets jsonip ipify icanhazip whatismyip plivo
messagebird kaspersky drweb bitdefender fortinet paloaltonetworks checkpoint
sentinelone carbonblack tanium qualys rapid7 tenable splunkcloud sumologic
loggly papertrailapp logz mixmax superhuman fastmail tutanota posteo runbox
startpage ecosia qwant mojeek biorxiv medrxiv ssrn overleaf zotero mendeley
mvnrepository jitpack jetbrains dnsmadeeasy ultradns dynect nsone stackpathdns
edgecastcdn 1e100 gvt1 2mdn""".split()

# Held out: never looked at while choosing a weight or a ramp, so a zero here is
# evidence the separation generalises rather than evidence of a good fit.
HOLDOUT_BENIGN = """wkbw wivb wgrz wham wroc wsyr wtvh wcax wmur wmtw wgme wcsh
kptv kgw katu koin kxl kink kupn kold kvoa kgun kmsb scdn spotifycdn
audioscrobbler lastfm bandcamp soundcloud mixcloud zscaler zscalertwo netskope
forcepoint ironport websense mimecast proofpoint barracuda sonicwall watchguard
cybs cybersource authorizenet braintreegateway adyen worldpay klarna afterpay
affirm sezzle fastspring paddle ncr diebold verifone ingenico squareup toasttab
lightspeedhq sabre amadeus travelport galileo worldspan sepa iso20022
fixprotocol wgu snhu asu byu ucf fsu utexas umich uiuc gatech kth chalmers dtu
ntnu aalto inria cnrs cea ipsl obspm polytechnique kek riken jaxa jaea nims
aist naoj ictp usenix csail eecs mitre s4hana hcl wipro infosys tcs cognizant
accenture capgemini deloitte kpmg mckinsey qlik tableau powerbi looker sisense
domo microstrategy teradata cloudera hortonworks databricks snowflakecomputing
mongodb couchbase cassandra scylladb influxdata timescale rabbitmq kafka pulsar
nats zeromq activemq haproxy traefik envoyproxy istio linkerd consul nomad
packer terraform vagrantup pulumi crossplane jenkins bamboo teamcity circleci
travis-ci drone buildkite sonarsource sonarqube snyk whitesourcesoftware
blackduck veracode hashicorp gruntwork spacelift scalr grsecurity kernelcare
tuxcare cloudlinux imunify360 plesk cpanel directadmin ispconfig virtualmin
webmin proxmox ovirt opennebula cloudstack truenas openmediavault unraid
synology qnap asustor pfsense opnsense untangle ipfire smoothwall zabbix nagios
icinga checkmk librenms observium cacti netbox nautobot phpipam infoblox bluecat
efficientip solarwinds manageengine paessler whatsupgold""".split()

ALL_BENIGN = BENIGN + SHORT_BENIGN + REAL_INFRA + HOLDOUT_BENIGN


def _random(rng, alphabet, low, high):
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(low, high)))


def conficker_style(rng, count):
    """Uniform lowercase letters, 8 to 14 characters, as Conficker emitted."""
    return [_random(rng, string.ascii_lowercase, 8, 14) for _ in range(count)]


def kraken_style(rng, count):
    """Consonant-heavy and unpronounceable, in the style of Kraken."""
    return [_random(rng, "bcdfghjklmnpqrstvwxz", 7, 12) for _ in range(count)]


def hex_style(rng, count):
    """Hash-looking names: the hex alphabet, mostly digits."""
    return [_random(rng, "0123456789abcdef", 12, 20) for _ in range(count)]


def alnum_style(rng, count):
    """Letters and digits mixed throughout, as later Necurs-era families did."""
    return [_random(rng, string.ascii_lowercase + string.digits, 10, 16)
            for _ in range(count)]


def short_style(rng, count):
    """Six to eight random letters: the family this detector is worst at."""
    return [_random(rng, string.ascii_lowercase, 6, 8) for _ in range(count)]


def families(seed=SEED, count=40):
    rng = random.Random(seed)
    return {
        "conficker": conficker_style(rng, count),
        "kraken": kraken_style(rng, count),
        "hex": hex_style(rng, count),
        "alnum": alnum_style(rng, count),
        "short": short_style(rng, count),
    }


def scored(labels, tld="com"):
    return [score_domain(f"{label}.{tld}") for label in labels]


def scores(labels, tld="com"):
    return [result.score for result in scored(labels, tld)]


def make_events(names, *, start=1000.0, step=0.5, responses=False):
    events = []
    for index, name in enumerate(names):
        events.append(DnsEvent(ts=start + index * step, client=CLIENT,
                               server=RESOLVER, name=name, qtype=1, rcode=0,
                               is_response=False))
        if responses:
            events.append(DnsEvent(ts=start + index * step + 0.01,
                                   client=CLIENT, server=RESOLVER, name=name,
                                   qtype=1, rcode=3, is_response=True))
    return events


# --- measured separation ---------------------------------------------------


def test_no_benign_domain_is_flagged():
    flagged = [(label, round(score, 2))
               for label, score in zip(ALL_BENIGN, scores(ALL_BENIGN))
               if score >= DEFAULT_THRESHOLD]
    assert flagged == []


def test_held_out_benign_names_are_not_flagged():
    """Weights were never fitted against these, so this is the honest number."""
    flagged = [(label, round(score, 2))
               for label, score in zip(HOLDOUT_BENIGN, scores(HOLDOUT_BENIGN))
               if score >= DEFAULT_THRESHOLD]
    assert flagged == []


@pytest.mark.parametrize("name", [
    "msftncsi.com",      # every Windows host, on every network connect
    "dns.msftncsi.com",
    "msftconnecttest.com",
    "hdfcbank.com",      # a bank, not a generator
    "lgtvsdp.com",       # LG televisions phoning home
    "mktdcdn.com", "smtcdns.net", "fbcdn.net", "crwdcntrl.net", "ggpht.com",
])
def test_ordinary_consonant_stacks_are_not_flagged(name):
    """These are bigram-indistinguishable from DGA output. Firing on any of
    them makes the detector unusable, whatever it scores on the malicious set."""
    assert score_domain(name).score < DEFAULT_THRESHOLD, score_domain(name).describe()


def test_correlated_letter_signals_cannot_reach_the_threshold_alone():
    """Bigram fit and pronounceability measure one fact. An all-letter name that
    maxes both and nothing else must stay unreported: that is what keeps every
    short consonant stack in the benign corpus below the line."""
    assert CORRELATED_WEIGHTS < DEFAULT_THRESHOLD


def test_benign_scores_keep_margin_below_the_threshold():
    """Zero false positives is not enough; there has to be room to spare."""
    worst = max(zip(scores(ALL_BENIGN), ALL_BENIGN))
    assert worst[0] <= DEFAULT_THRESHOLD - 0.05, worst


def test_measured_accuracy_and_false_positive_rate():
    """Regression guard on the numbers this detector is claimed to achieve."""
    benign = scores(ALL_BENIGN)
    malicious = [score for names in families().values() for score in scores(names)]

    false_positives = sum(score >= DEFAULT_THRESHOLD for score in benign)
    true_positives = sum(score >= DEFAULT_THRESHOLD for score in malicious)
    fpr = false_positives / len(benign)
    recall = true_positives / len(malicious)
    accuracy = (len(benign) - false_positives + true_positives) / (len(benign) + len(malicious))

    assert fpr == 0.0
    assert recall >= 0.68, recall
    assert accuracy >= 0.90, accuracy


@pytest.mark.parametrize("family,floor", [
    ("conficker", 0.70),
    ("kraken", 0.85),
    ("hex", 0.90),
    ("alnum", 0.75),
])
def test_family_recall(family, floor):
    values = scores(families()[family])
    recall = sum(score >= DEFAULT_THRESHOLD for score in values) / len(values)
    assert recall >= floor, (family, recall)


def test_short_random_names_are_the_documented_weak_case():
    """Six to eight random letters is where this method runs out of evidence.
    A seven-character consonant stack is the same object whether LG registered
    it or a generator emitted it, so recall here is near zero on purpose."""
    values = scores(families()["short"])
    recall = sum(score >= DEFAULT_THRESHOLD for score in values) / len(values)
    assert recall < 0.25, recall


def test_a_seven_letter_generated_name_is_indistinguishable_from_lgtvsdp():
    """The reason short recall is abandoned rather than tuned. These two differ
    only in who registered them."""
    benign = score_domain("lgtvsdp.com")
    generated = score_domain("gbpplvl.com")
    assert abs(benign.score - generated.score) < 0.12
    assert max(benign.score, generated.score) < DEFAULT_THRESHOLD


def test_syllable_generators_evade_lexical_scoring():
    """Alternating consonants and vowels costs an attacker nothing and produces
    pronounceable names built from ordinary letters. Lexical scoring cannot see
    them; this pins the cheapest available evasion as a known miss."""
    rng = random.Random(SEED)
    consonants, vowels = "bcdfghjklmnprstvwz", "aeiou"
    names = ["".join(rng.choice(consonants) + rng.choice(vowels)
                     for _ in range(rng.randint(4, 6))) for _ in range(60)]
    caught = sum(score >= DEFAULT_THRESHOLD for score in scores(names))
    assert caught / len(names) < 0.10, caught


def test_wordlist_dga_is_not_detected():
    """Pins the blind spot: matsnu/suppobox names are made of English."""
    assert all(score < DEFAULT_THRESHOLD for score in scores(WORDLIST_DGA))


# --- components ------------------------------------------------------------


def test_bigram_fit_ranks_pronounceable_above_random():
    assert score_domain("facebook.com").bigram > score_domain("xkqjzbwrt.com").bigram


def test_consonant_run_and_vowel_ratio():
    kraken = score_domain("xkqjzbwrt.com")
    assert kraken.consonant_run == 9
    assert kraken.vowel_ratio == 0.0
    assert kraken.pronounce_score == 1.0

    normal = score_domain("wikipedia.com")
    assert normal.consonant_run <= 2
    assert normal.pronounce_score < 0.05


def test_entropy_counts_repeated_characters():
    assert score_domain("aaaaaaaaaa.com").entropy == 0.0
    assert score_domain("abcdefghij.com").entropy == pytest.approx(math.log2(10))


def test_digits_at_the_edge_are_ordinary_but_interleaved_digits_are_not():
    edge = score_domain("office365.com")
    interleaved = score_domain("o5f2f9i8c4e3.com")
    assert edge.digit_score < 0.25
    assert interleaved.digit_score > 0.9
    # Same letters either way, so the placement of the digits is the whole
    # difference in the verdict.
    assert edge.score < interleaved.score - 0.25


def test_digit_heavy_names_are_judged_on_shape_not_bigrams():
    """Too few letters to fit bigrams, so the verdict must rest elsewhere."""
    result = score_domain("1c4e1517b560e945d8.com")
    assert result.bigram_score < 0.2      # the letters left over look fine
    assert result.score >= DEFAULT_THRESHOLD


def test_length_damping_protects_short_names():
    assert score_domain("xkcd.com").confidence < score_domain("xkcdxkcdx.com").confidence
    assert score_domain("qzk.com").score < score_domain("qzkqzkqzkqzk.com").score


def test_components_are_reported_and_frozen():
    result = score_domain("kqvzjhbmwx.net")
    assert isinstance(result, DgaScore)
    assert result.label == "kqvzjhbmwx"
    assert result.domain == "kqvzjhbmwx.net"
    assert result.length == 10
    assert 0.0 <= result.score <= 1.0
    assert "kqvzjhbmwx.net" in result.describe()
    with pytest.raises(Exception):
        result.score = 0.0


# --- name extraction -------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("www.google.com", "google.com"),
    ("GOOGLE.COM", "google.com"),
    ("a.b.c.example.org", "example.org"),
    ("news.bbc.co.uk", "bbc.co.uk"),
    ("example.com.", "example.com"),
])
def test_registrable_extraction(name, expected):
    assert registrable(name) == expected


@pytest.mark.parametrize("name", [
    "", ".", "printer.local", "9.0.0.10.in-addr.arpa",
    "_googlecast._tcp.local", "xn--80ak6aa92e.com", "host.internal",
    "a" * 300 + ".com",
])
def test_unscorable_names_are_skipped(name):
    assert score_domain(name) is None


def test_subdomains_do_not_change_the_verdict():
    """Only the registered label is judged; a CDN's opaque left labels are not."""
    assert score_domain("d3f7k2m9x1q4.cloudfront.net").score == score_domain("cloudfront.net").score


def test_multi_part_suffix_scores_the_registered_label():
    assert score_domain("qvzxjkwbmr.co.uk").label == "qvzxjkwbmr"
    assert score_domain("qvzxjkwbmr.co.uk").score >= DEFAULT_THRESHOLD


def test_find_dga_ignores_single_label_queries():
    """Bare names are resolver noise (wpad, isatap, a hostname) with no
    registration behind them, though score_domain will still judge a label."""
    assert find_dga(make_events(["wpad", "isatap", "kqvzjhbmwx"])) == []
    assert score_domain("kqvzjhbmwx") is not None


def test_bare_label_and_full_name_agree():
    assert score_domain("facebook").score == score_domain("facebook.com").score


# --- find_dga over DNS events ----------------------------------------------


def test_find_dga_reports_generated_names_worst_first():
    rng = random.Random(SEED)
    names = [f"{label}.com" for label in kraken_style(rng, 5)]
    events = make_events(names + ["www.google.com", "github.com"], responses=True)

    found = find_dga(events)
    assert [result.domain for result in found] == sorted(
        (result.domain for result in found),
        key=lambda domain: -score_domain(domain).score)
    assert set(name.removesuffix(".") for name in names) >= {r.domain for r in found}
    assert {"google.com", "github.com"} & {r.domain for r in found} == set()


def test_each_name_is_scored_once_however_often_it_is_queried():
    names = ["kqvzjhbmwx.com"] * 50 + ["www.kqvzjhbmwx.com"] * 20
    found = find_dga(make_events(names))
    assert len(found) == 1
    assert found[0].domain == "kqvzjhbmwx.com"


def test_threshold_is_respected():
    events = make_events(["kqvzjhbmwx.com", "google.com"])
    assert find_dga(events, threshold=0.99) == []
    assert len(find_dga(events, threshold=0.0)) == 2


def test_max_names_bounds_the_work():
    rng = random.Random(SEED)
    names = [f"{label}.com" for label in conficker_style(rng, 200)]
    assert len(find_dga(make_events(names), max_names=10)) <= 10


def test_empty_input():
    assert find_dga([]) == []


# --- hostile input ---------------------------------------------------------

HOSTILE = [
    "", ".", "..", "...", "a", "a.", ".com", "..com", "a..com",
    "\x00.\x00", "\x00null.com", "-.-", "----------.com", "..........",
    "a" * 63 + ".com", "a" * 64 + ".com", ("a." * 100) + "com",
    "ünïcödé.com", "٣٤٥.com",
    "²³.com", "123456789012345.com", "0.0.0.0", " padded .com",
    "example.com" + "\n", "tab\there.com",
]


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_names_never_raise(name):
    result = score_domain(name)
    assert result is None or 0.0 <= result.score <= 1.0


def test_hostile_names_survive_find_dga():
    found = find_dga(make_events(HOSTILE))
    assert all(0.0 <= result.score <= 1.0 for result in found)


def test_a_repeated_character_is_not_generated_output():
    """A run of one character is the least random string there is. The bigram
    model still dislikes "aa", so without a check on how much distinct material
    the name actually carries it scores like a long generated name."""
    for name in ["aaaaaaaaaa.com", "wwwwwwwwwwwwwwww.net", "a" * 63 + ".org",
                 "abababababababab.com"]:
        result = score_domain(name)
        assert result.score < DEFAULT_THRESHOLD, result.describe()


def test_the_length_limit_is_not_bypassed_by_a_bare_label():
    """registrable() rejects names over 255 octets. The bare-label path has to
    reject them too, or the same string is unscorable with a suffix and scored
    without one."""
    assert score_domain("a" * 300) is None
    assert score_domain("deadbeef1234" * 25) is None


def test_random_bytes_as_names_never_raise():
    rng = random.Random(SEED)
    for _ in range(500):
        raw = bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
        name = raw.decode("latin-1")
        result = score_domain(name)
        assert result is None or 0.0 <= result.score <= 1.0


# --- the generated model ---------------------------------------------------

REPO = Path(__file__).resolve().parents[1]
WORDLIST = Path("/usr/share/dict/words")


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_bigrams", REPO / "tools" / "build_bigrams.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_table_shape_and_normalisation():
    assert len(ALPHABET) == 27
    assert len(LOG_PROB) == 27
    for row in LOG_PROB:
        assert len(row) == 27
        assert all(value < 0 for value in row)
        assert sum(math.exp(value) for value in row) == pytest.approx(1.0, abs=1e-3)


def test_letter_marginals_are_a_distribution_that_ranks_english():
    assert len(LETTER_LOG_PROB) == 26
    assert sum(math.exp(value) for value in LETTER_LOG_PROB) == pytest.approx(1.0, abs=1e-3)
    index = lambda char: LETTER_LOG_PROB[ord(char) - 97]
    assert index("e") > index("s") > index("k") > index("q")


def test_unseen_pairs_are_penalised_but_finite():
    unseen = LOG_PROB[INDEX["q"]][INDEX["x"]]
    common = LOG_PROB[INDEX["q"]][INDEX["u"]]
    assert math.isfinite(unseen)
    assert unseen < common - 5


def test_builder_is_deterministic(tmp_path):
    builder = load_builder()
    words = tmp_path / "words"
    words.write_text("apple\nbanana\nAPPLE\ncherry\nx\nno-alpha1\n")
    first, second = tmp_path / "a.py", tmp_path / "b.py"
    assert builder.main([str(words), "-o", str(first)]) == 0
    assert builder.main([str(words), "-o", str(second)]) == 0
    assert first.read_text() == second.read_text()
    assert "3 words" in first.read_text()


def test_builder_smoothing_matches_by_hand(tmp_path):
    builder = load_builder()
    words = tmp_path / "words"
    words.write_text("ab\n")
    out = tmp_path / "table.py"
    builder.main([str(words), "-o", str(out)])
    namespace: dict = {}
    exec(compile(out.read_text(), str(out), "exec"), namespace)
    # "^ab^": one ^a, so P(a|^) = (1 + 1) / (1 + 27).
    assert namespace["LOG_PROB"][0][1] == pytest.approx(math.log(2 / 28), abs=1e-4)


def test_builder_rejects_a_missing_wordlist(tmp_path, capsys):
    builder = load_builder()
    assert builder.main([str(tmp_path / "nope"), "-o", str(tmp_path / "o.py")]) == 1


@pytest.mark.skipif(not WORDLIST.is_file(), reason="no system wordlist")
def test_committed_table_matches_the_wordlist(tmp_path):
    """The committed table has to be exactly what the generator produces."""
    builder = load_builder()
    out = tmp_path / "bigrams.py"
    assert builder.main([str(WORDLIST), "-o", str(out)]) == 0
    committed = REPO / "src" / "pcapinator" / "detect" / "bigrams.py"
    assert out.read_text() == committed.read_text()
