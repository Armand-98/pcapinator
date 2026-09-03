#!/usr/bin/env python3
"""Regenerate src/pcapinator/detect/bigrams.py from a wordlist.

Source: /usr/share/dict/words (the BSD web2 list, 235976 entries), the same
list present on any macOS or BSD host. Only ASCII alphabetic entries of two or
more characters are used, lowercased.

Two tables are emitted. LOG_PROB is a 27x27 matrix of natural log conditional
probabilities P(next | previous) over a boundary symbol plus a to z. Row 0 and
column 0 are the boundary, so a word contributes ^f, fo, oo, ... , od$.
LETTER_LOG_PROB is the marginal log P(letter) over the same corpus: which
letters a human reaches for, independent of the order they are put in.

Counts are Laplace smoothed, which is what keeps an unseen pair finite: it costs
about -12 nats instead of -inf, a heavy but bounded penalty.

Deterministic: sorted input, integer counts, values rounded to 4 decimals.

Usage: python tools/build_bigrams.py [wordlist] [-o output.py]
"""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

ALPHABET = "^abcdefghijklmnopqrstuvwxyz"
SIZE = len(ALPHABET)
INDEX = {char: pos for pos, char in enumerate(ALPHABET)}
ALPHA = 1.0   # Laplace smoothing weight
DEFAULT_WORDLIST = Path("/usr/share/dict/words")
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "src/pcapinator/detect/bigrams.py"

HEADER = '''"""Character model of human-chosen names. GENERATED, do not edit.

Built by tools/build_bigrams.py from {source} ({words} words, {pairs} bigrams).
LOG_PROB is the natural log of P(next | previous) over the alphabet "^" plus
a-z, where "^" is the word boundary, Laplace smoothed with alpha={alpha:g} so an
unseen pair costs {floor:.2f} nats rather than negative infinity. LETTER_LOG_PROB is
the marginal log P(letter): which letters get chosen, ignoring their order.

Index a transition as LOG_PROB[INDEX[prev]][INDEX[next]] and a letter's
marginal as LETTER_LOG_PROB[ord(char) - 97].
"""

ALPHABET = {alphabet!r}
INDEX = {{char: pos for pos, char in enumerate(ALPHABET)}}
UNSEEN = {floor:.4f}

LOG_PROB = (
'''


def read_words(path: Path) -> list[str]:
    words = set()
    with path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip().lower()
            if len(word) >= 2 and all("a" <= char <= "z" for char in word):
                words.add(word)
    return sorted(words)


def count_bigrams(words: list[str]) -> tuple[list[list[int]], list[int], int]:
    counts = [[0] * SIZE for _ in range(SIZE)]
    letters = [0] * 26
    pairs = 0
    for word in words:
        symbols = "^" + word + "^"
        for prev, nxt in zip(symbols, symbols[1:]):
            counts[INDEX[prev]][INDEX[nxt]] += 1
            pairs += 1
        for char in word:
            letters[ord(char) - 97] += 1
    return counts, letters, pairs


def to_letter_log_probs(letters: list[int]) -> list[float]:
    total = sum(letters) + ALPHA * 26
    return [round(math.log((value + ALPHA) / total), 4) for value in letters]


def to_log_probs(counts: list[list[int]]) -> list[list[float]]:
    table = []
    for row in counts:
        total = sum(row) + ALPHA * SIZE
        table.append([round(math.log((value + ALPHA) / total), 4) for value in row])
    return table


def render(table: list[list[float]], letters: list[float], source: Path,
           words: int, pairs: int, floor: float) -> str:
    out = [HEADER.format(source=source, words=words, pairs=pairs, alpha=ALPHA,
                         floor=floor, alphabet=ALPHABET)]
    for pos, row in enumerate(table):
        values = ", ".join(f"{value:.4f}" for value in row)
        out.append(f"    # {ALPHABET[pos]}\n    ({values}),\n")
    out.append(")\n\n# marginal log P(letter), a to z\nLETTER_LOG_PROB = (\n")
    for start in range(0, 26, 9):
        chunk = letters[start:start + 9]
        out.append("    " + ", ".join(f"{value:.4f}" for value in chunk) + ",\n")
    out.append(")\n")
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wordlist", nargs="?", type=Path, default=DEFAULT_WORDLIST)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    if not args.wordlist.is_file():
        print(f"wordlist not found: {args.wordlist}", file=sys.stderr)
        return 1

    words = read_words(args.wordlist)
    if not words:
        print(f"no usable words in {args.wordlist}", file=sys.stderr)
        return 1

    counts, letter_counts, pairs = count_bigrams(words)
    table = to_log_probs(counts)
    letters = to_letter_log_probs(letter_counts)
    # Worst case cost of a pair the wordlist never showed, taken from the
    # busiest row: that row's smoothing mass is spread thinnest.
    floor = min(min(row) for row in table)
    args.output.write_text(
        render(table, letters, args.wordlist, len(words), pairs, floor))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
