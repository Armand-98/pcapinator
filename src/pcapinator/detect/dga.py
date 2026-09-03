"""Algorithmically generated domain scoring.

Malware that hides its C2 behind a domain generation algorithm queries names no
human would register. The difference is lexical, so a name is scored on its own
text, with no reference to whether it resolved: NXDOMAIN evidence is real but it
is also the first thing a sinkhole or a wildcard registrar destroys, and keeping
the score purely lexical makes it reproducible from the name alone.

Six components, none of them conclusive alone:

  bigram fit        mean log P(next | previous) of the name's letters under a
                    character bigram model built from /usr/share/dict/words.
                    This is the primary signal: "facebook" is made of pairs
                    English uses constantly, "xkqjzbwrt" is not.
  letter choice     mean log P(letter) under the same corpus, ignoring order.
                    A generator samples its alphabet uniformly and so reaches
                    for q, x, z and j at the same rate as e and s; a human
                    picking a name does not. Uniform draws from a-z average
                    -3.95 nats per letter and from a consonant alphabet -4.27,
                    against about -3.0 for chosen names.
  pronounceability  vowel ratio and longest consonant run. A generated string
                    drawn uniformly from the alphabet lands near 19% vowels
                    against about 38% for chosen names, and stacks consonants
                    no one could say.
  entropy           Shannon entropy over the characters. Chosen names repeat
                    letters and reuse a small set; random ones do not.
  length            generated names are long, because short ones collide with
                    names that are already registered.
  digits            digit ratio, weighted by placement. Digits are ordinary in
                    real domains when they sit at one end ("office365", "s3",
                    "3m"); digits threaded through the letters are not.

Signals that read the letters (bigram fit, letter choice, pronounceability)
carry weight in proportion to how much of the name is letters, and the weight
they give up passes to the signals that read shape. That is what catches
hex-style names: "1c4e1517b560e945d8" has too few letters to say anything about
its bigrams, so the verdict rests on its digits, entropy and length instead.

Bigram fit and pronounceability are not independent evidence: an unsayable
consonant stack is improbable under the bigram model for the same reason it is
unsayable, so a name scoring badly on one scores badly on the other. Their
weights therefore sum below the reporting threshold, and no name can be reported
on that single fact. This matters because real DNS is full of short consonant
stacks - msftncsi.com is queried by every Windows host on the network, hdfcbank
and lgtvsdp and mktdcdn and fbcdn are ordinary registrations - and every one of
them is bigram-indistinguishable from generated output. What separates them is
letter choice: they are built from common English letters, while a generator
spends a third of its draws on rare ones.

Short names are damped rather than trusted: "xkcd" and "npmjs" are as
improbable as anything a DGA emits, and four characters cannot tell them apart.

On the labelled set in tests/test_dga.py (real domains, including an
infrastructure corpus and a held-out corpus never used to fit a weight, against
200 names from five generator styles) this scores 0.92 accuracy at 0.70 recall
with no false positives, and the worst benign name lands 0.06 below the
threshold.

Benign patterns deliberately tested against (tests/test_dga.py):
  - popular real domains, including consonant-heavy ones (npmjs, xkcd, wsj,
    ndtv) and coined brand names (spotify, twilio, akamai, shopify)
  - non-English brands (yandex, xiaomi, seznam, bilibili, wildberries), which
    an English model has every reason to dislike
  - short domains: two and three letter names and shorteners
  - domains carrying digits (office365, live365, s3, web2, 3m, log4j, sha256,
    route53, w3schools)
  - CDN and cloud hostnames whose left labels are opaque, since only the
    registrable label is scored
  - an infrastructure corpus a browsing-history benign set misses entirely:
    connectivity checks (msftncsi, msftconnecttest), CDN and ad-tech shorthand
    (fbcdn, crwdcntrl, ggpht, smtcdns, jsdelivr), nameserver zones
    (gtld-servers, awsdns-08, nstld), IoT back ends (lgtvsdp), broadcast call
    signs (wkbw, kmsb) and non-English banks (hdfcbank, icicibank)
  - a held-out benign corpus never consulted while fitting a weight or a ramp
  - reverse lookups (in-addr.arpa and ip6.arpa), mDNS and Bonjour service names,
    Active Directory SRV names under _msdcs, Kubernetes cluster.local names,
    EC2 .internal hostnames, DNSBL lookups, .local and bare single labels, which
    are skipped
  - a label that is one character repeated, which carries no evidence at all

Known false-positive and false-negative classes:
  - wordlist DGAs (matsnu, suppobox, gozi) chain real dictionary words. They
    score like English because they are English. This method cannot see them;
    that needs query volume and NXDOMAIN rates, not lexical scoring.
  - punycode (xn--) labels are machine-encoded IDN and score as random, so they
    are exempted outright. A DGA registering an IDN is therefore invisible.
  - names of four characters or fewer are unreliable in both directions and are
    damped hard enough that they are effectively never reported. Seven-character
    all-consonant labels are no better: the benign "lgtvsdp" and a generated
    "gbpplvl" are identical on every lexical measure, so both sit below the
    threshold and generated names that short are missed by design.
  - a generator that alternates consonants and vowels ("vasacosabusi") is
    pronounceable, uses ordinary letters and fits the bigram model, so it scores
    like a coined brand name and is missed entirely. This is the cheapest
    evasion available and it defeats lexical scoring outright.
  - abbreviation-heavy and non-English brand names are the residual false
    positives; the model only knows English.
  - the multi-part suffix table below is a fixed list, not the public suffix
    list, which is a data file this tool deliberately does not ship. A name
    registered under an unlisted suffix has that suffix's label scored instead
    of the generated one, and is missed.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from ..dnsview import DnsEvent
from .bigrams import INDEX, LETTER_LOG_PROB, LOG_PROB

VOWELS = frozenset("aeiouy")
MAX_NAME = 255          # a DNS name cannot exceed this; hostile names can
MAX_LABEL = 63          # nor can a single label
MAX_NAMES = 100_000     # distinct names scored per capture, to bound memory

# Bigram fit of ordinary names sits near -2.8 nats per transition; uniformly
# random letters sit near -5. The ramp is placed between the two.
BIGRAM_GOOD = -3.2
BIGRAM_BAD = -4.6

# Mean log P(letter). Chosen names sit near -3.0; letters drawn uniformly from
# a-z average -3.95 and from a consonant-only alphabet -4.27. The ramp is placed
# between the human region and the uniform one.
LETTER_FREQ_GOOD = -3.2
LETTER_FREQ_BAD = -4.1

ENTROPY_LOW = 2.8       # bits; below this the name reuses characters
ENTROPY_HIGH = 3.9

# Registrable labels people choose cluster at four to ten characters; generated
# ones start around eight and run long.
LENGTH_SHORT = 7
LENGTH_LONG = 16

VOWEL_LOW = 0.35        # English words run about 0.38
VOWEL_STARVED = 0.10
VOWEL_RICH = 0.55
VOWEL_FLOODED = 0.80

CONSONANT_RUN_OK = 4    # "nights" reaches 4
CONSONANT_RUN_BAD = 7

DIGIT_LOW = 0.12
DIGIT_HIGH = 0.45
# Digits at one end of a name are a version or a brand; digits between letters
# are a generator.
DIGIT_EDGE_ONLY = 0.30

WEIGHT_BIGRAM = 0.38
WEIGHT_LETTER_FREQ = 0.18
WEIGHT_PRONOUNCE = 0.08
WEIGHT_ENTROPY = 0.06
WEIGHT_LENGTH = 0.18
WEIGHT_DIGIT = 0.12
LETTER_WEIGHTS = WEIGHT_BIGRAM + WEIGHT_LETTER_FREQ + WEIGHT_PRONOUNCE
# Bigram fit and pronounceability measure the same fact, so on their own they
# must not be able to reach the threshold.
CORRELATED_WEIGHTS = WEIGHT_BIGRAM + WEIGHT_PRONOUNCE

# Confidence in any lexical verdict grows with the number of characters there
# are to judge. It never reaches zero, so a short name is reported when every
# signal agrees, and never on one signal alone. Repeats do not count as more
# material: "a" repeated sixty times is no more evidence than "aaa", and the
# bigram model dislikes "aa" enough to flag it if length is taken at face value.
CONFIDENCE_FLOOR = 0.45
CONFIDENCE_SHORT = 3
CONFIDENCE_FULL = 9
CONFIDENCE_REPEATS = 3  # characters of credit per distinct character

DEFAULT_THRESHOLD = 0.55

# Suffixes under which registrations happen one label further left, so the name
# a DGA actually chose is not the second label from the right.
MULTI_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk net.uk me.uk ltd.uk plc.uk sch.uk
com.au net.au org.au edu.au gov.au id.au
co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr co.nz net.nz org.nz govt.nz
co.za org.za web.za co.il org.il ac.il co.in net.in org.in gen.in firm.in
com.br net.br org.br gov.br com.mx com.ar com.co com.pe com.ve com.uy
com.cn net.cn org.cn gov.cn edu.cn com.hk com.tw com.sg com.my com.ph
com.tr com.pl com.ua com.ru com.vn co.th com.pk com.sa com.eg com.ng
""".split())

_LOCAL_SUFFIXES = ("arpa", "local", "localdomain", "internal", "lan", "home",
                   "onion", "invalid", "test", "example")


@dataclass(frozen=True, slots=True)
class DgaScore:
    domain: str             # registrable-looking name the label was taken from
    label: str              # the label actually scored
    length: int
    bigram: float           # mean log probability per transition, nats
    letter_freq: float      # mean log probability per letter, nats
    entropy: float          # bits per character
    vowel_ratio: float
    consonant_run: int
    digit_ratio: float
    bigram_score: float
    letter_freq_score: float
    pronounce_score: float
    entropy_score: float
    length_score: float
    digit_score: float
    confidence: float
    score: float

    def describe(self) -> str:
        return (f"{self.domain} score {self.score:.2f} "
                f"(bigram {self.bigram:.2f}/t, letters {self.letter_freq:.2f}/c, "
                f"entropy {self.entropy:.2f}b, "
                f"vowels {self.vowel_ratio:.0%}, "
                f"consonant run {self.consonant_run}, "
                f"digits {self.digit_ratio:.0%})")


def find_dga(events: Iterable[DnsEvent], *,
             threshold: float = DEFAULT_THRESHOLD,
             max_names: int = MAX_NAMES) -> list[DgaScore]:
    """Score every distinct name queried and return the generated-looking ones.

    Each registrable name is scored once however often it was asked for, so a
    single noisy resolver cannot flood the report.
    """
    seen: set[str] = set()
    found: list[DgaScore] = []
    for event in events:
        domain = registrable(event.name)
        if not domain or domain in seen:
            continue
        if len(seen) >= max_names:
            break
        seen.add(domain)
        result = score_domain(domain)
        if result is not None and result.score >= threshold:
            found.append(result)
    found.sort(key=lambda item: item.score, reverse=True)
    return found


def score_domain(name: str) -> DgaScore | None:
    """Score one name. Accepts a full name or a bare label.

    Returns None for names there is nothing to judge: empty, punycode, or with
    no alphanumeric content.
    """
    domain = registrable(name)
    if not domain:
        # A bare label with no suffix is scorable; anything registrable()
        # rejected as a name is not, including names past the 255 octet limit.
        if "." in name.strip(".") or len(name) > MAX_NAME:
            return None
        domain = name.strip().strip(".").lower()
    label = _scored_label(domain)
    if not label:
        return None

    letters = [char for char in label if "a" <= char <= "z"]
    digits = [char for char in label if char.isdigit()]
    length = len(label)
    letter_share = len(letters) / length

    bigram = _bigram_fit(letters)
    letter_freq = _letter_freq(letters)
    entropy = _entropy(label)
    vowel_ratio = sum(char in VOWELS for char in letters) / len(letters) if letters else 0.0
    consonant_run = _longest_consonant_run(letters)
    digit_ratio = len(digits) / length

    bigram_score = _ramp(bigram, BIGRAM_GOOD, BIGRAM_BAD)
    letter_freq_score = _ramp(letter_freq, LETTER_FREQ_GOOD, LETTER_FREQ_BAD)
    pronounce_score = 0.5 * (_vowel_score(vowel_ratio, len(letters))
                             + _ramp(consonant_run, CONSONANT_RUN_OK,
                                     CONSONANT_RUN_BAD))
    entropy_score = _ramp(entropy, ENTROPY_LOW, ENTROPY_HIGH)
    length_score = _ramp(length, LENGTH_SHORT, LENGTH_LONG)
    digit_score = _digit_score(label, digit_ratio, bool(letters))

    raw = _combine(letter_share, [
        (WEIGHT_BIGRAM, bigram_score),
        (WEIGHT_LETTER_FREQ, letter_freq_score),
        (WEIGHT_PRONOUNCE, pronounce_score),
    ], [
        (WEIGHT_ENTROPY, entropy_score),
        (WEIGHT_LENGTH, length_score),
        (WEIGHT_DIGIT, digit_score),
    ])
    evidence = min(length, CONFIDENCE_REPEATS * len(set(label)))
    confidence = CONFIDENCE_FLOOR + (1.0 - CONFIDENCE_FLOOR) * _ramp(
        evidence, CONFIDENCE_SHORT, CONFIDENCE_FULL)

    return DgaScore(
        domain=domain, label=label, length=length,
        bigram=bigram, letter_freq=letter_freq, entropy=entropy,
        vowel_ratio=vowel_ratio,
        consonant_run=consonant_run, digit_ratio=digit_ratio,
        bigram_score=bigram_score, letter_freq_score=letter_freq_score,
        pronounce_score=pronounce_score,
        entropy_score=entropy_score, length_score=length_score,
        digit_score=digit_score, confidence=confidence,
        score=_clamp(raw * confidence),
    )


def registrable(name: str) -> str:
    """The name a registration would have been made under, lowercased.

    Empty for anything not worth scoring: single labels, reverse lookups, mDNS
    service names, and local-only namespaces.
    """
    if not name or len(name) > MAX_NAME:
        return ""
    labels = [label for label in name.strip().lower().split(".") if label]
    if len(labels) < 2 or labels[-1] in _LOCAL_SUFFIXES:
        return ""
    if any(label.startswith("_") for label in labels):
        return ""

    depth = 3 if ".".join(labels[-2:]) in MULTI_SUFFIXES else 2
    if len(labels) < depth:
        return ""
    return ".".join(labels[-depth:])


def _scored_label(domain: str) -> str:
    """The single label a generator would have chosen, or empty if unscorable."""
    # registrable() returns the registered label followed by its suffix, so the
    # generator's choice is always the leftmost one.
    label = domain.split(".")[0][:MAX_LABEL]
    if label.startswith("xn--"):
        return ""
    return label if any(char.isalnum() for char in label) else ""


def _combine(letter_share: float, letter_parts: list[tuple[float, float]],
             shape_parts: list[tuple[float, float]]) -> float:
    """Weighted mean where letter-based signals are trusted in proportion to
    how much of the name is letters, and hand the rest of their weight over."""
    letter_weight = LETTER_WEIGHTS * letter_share
    shape_weight = 1.0 - letter_weight
    shape_base = sum(weight for weight, _ in shape_parts)

    total = sum(weight * letter_share * value for weight, value in letter_parts)
    total += sum(weight / shape_base * shape_weight * value
                 for weight, value in shape_parts)
    return total


def _bigram_fit(letters: list[str]) -> float:
    """Mean log probability per transition of the name's letters, boundaries
    included. Digits and hyphens are transparent: they are judged separately,
    and splitting on them would leave one-letter fragments that score well by
    accident."""
    if not letters:
        return BIGRAM_GOOD
    symbols = "^" + "".join(letters) + "^"
    total = sum(LOG_PROB[INDEX[prev]][INDEX[nxt]]
                for prev, nxt in zip(symbols, symbols[1:]))
    return total / (len(symbols) - 1)


def _letter_freq(letters: list[str]) -> float:
    """Mean log probability of the letters themselves, order ignored. This is
    the axis a consonant-stack abbreviation passes and a generator fails: both
    are unpronounceable, but only the generator spends its draws on q, x and z."""
    if not letters:
        return LETTER_FREQ_GOOD
    return sum(LETTER_LOG_PROB[ord(char) - 97] for char in letters) / len(letters)


def _entropy(label: str) -> float:
    counts = Counter(label)
    length = len(label)
    return -sum((count / length) * math.log2(count / length)
                for count in counts.values())


def _longest_consonant_run(letters: list[str]) -> int:
    longest = run = 0
    for char in letters:
        run = 0 if char in VOWELS else run + 1
        longest = max(longest, run)
    return longest


def _vowel_score(ratio: float, letters: int) -> float:
    if letters < 3:
        return 0.0
    return max(_ramp(ratio, VOWEL_LOW, VOWEL_STARVED),
               _ramp(ratio, VOWEL_RICH, VOWEL_FLOODED))


def _digit_score(label: str, ratio: float, has_letters: bool) -> float:
    if ratio <= 0:
        return 0.0
    placement = 1.0 if not has_letters else _placement(label)
    return _ramp(ratio, DIGIT_LOW, DIGIT_HIGH) * placement


def _placement(label: str) -> float:
    """How unusual the digits sit. A group touching either end of the name is a
    version or a brand; groups walled in by letters are how generators emit
    them."""
    interior = 0
    start = None
    for index, char in enumerate(label + " "):
        if char.isdigit():
            if start is None:
                start = index
            continue
        if start is not None and start > 0 and index < len(label):
            interior += 1
        start = None
    if interior == 0:
        return DIGIT_EDGE_ONLY
    return min(1.0, 0.5 + 0.25 * interior)


def _ramp(value: float, low: float, high: float) -> float:
    """0 at low, 1 at high, linear between. Works in either direction."""
    if high == low:
        return 0.0
    return _clamp((value - low) / (high - low))


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
