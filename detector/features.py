"""Per-client feature extraction from request logs.

Every feature here is deliberately **rate-independent and sample-size
normalised**. Query volume is the obvious extraction signal and the easiest
one to evade -- an attacker who throttles to human pace defeats it at no cost
but time. Features that depend on n or on requests/sec were therefore left
out, so the detector is forced to work from the *shape* of the queries and
their timing rather than their volume.

Each feature is a bounded ratio, so a client sending 30 requests and one
sending 3000 land on the same scale.
"""

import json
import math
from collections import Counter
from difflib import SequenceMatcher

# Two queries count as near-duplicates above this token-overlap (Jaccard).
# Fixed a priori, not tuned: 0.6 means "most words shared".
NEAR_DUP_JACCARD = 0.6

# Cap on pairwise comparisons. Near-duplicate detection is O(n^2); above this
# many requests a random sample gives the same ratio far more cheaply.
MAX_PAIRWISE = 400

# edit_neighbour_rate. Boundary probing has to send a query and a slightly
# edited copy of it, so it leaves pairs of DIFFERENT queries that are close
# in word order, not just in word overlap. Two queries are edit neighbours
# when their word sequences are at least this similar (difflib ratio, where
# 1.0 is identical). Chosen before any result was seen: 0.6 means about
# three of every five words line up in order, which is what a handful of
# edits to one sentence leaves behind and what two unrelated sentences do not.
EDIT_NEIGHBOUR_RATIO = 0.6

# The signal looks over this many requests: the 30 being scored plus up to
# this many before them. A prober can keep a query and its edited copy more
# than 30 requests apart so they never share a window, and that is exactly
# the evasion this is meant to close (see eval/adaptive_attacker.py).
WIDE_EXTRA = 30

# Features that are proportions of a window. A proportion measured over W
# requests moves in steps of 1/W, so deviations smaller than one step are
# quantisation noise, not signal. calibrate.py uses this to floor their scale
# -- without it, a feature that happens to be all-zero across the benign
# sample has zero spread, and one odd request becomes a 30-sigma event.
PROPORTION_FEATURES = frozenset({
    "exact_dup_rate",
    "near_dup_rate",
    "template_share",
    "low_conf_rate",
    "edit_neighbour_rate",
    # label_balance is |p - 0.5| for a proportion p, so it inherits the same
    # 1/W resolution. Without it here, a client with a perfectly even label
    # split scored an 18-sigma deviation purely because the benign MAD was
    # tiny -- an artefact, not a signal.
    "label_balance",
})

FEATURE_NAMES = (
    "exact_dup_rate",
    "near_dup_rate",
    "herdan_c",
    "token_entropy_norm",
    "len_cv",
    "template_share",
    "low_conf_rate",
    "conf_p10",
    "iat_burstiness",
    "label_balance",
    "edit_neighbour_rate",
)


def _mean(xs):
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def _std(xs):
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


# --- Lexical shape ---------------------------------------------------------

def _near_dup_rate(texts, rng=None):
    """Share of queries that closely resemble at least one other query.

    Boundary probing produces many near-identical inputs; random sampling of
    the input space produces almost none. The two attack styles sit at
    opposite ends, which is why the score below treats deviation in *either*
    direction as suspicious.
    """
    if len(texts) < 2:
        return 0.0
    sample = texts
    if len(texts) > MAX_PAIRWISE and rng is not None:
        sample = rng.sample(texts, MAX_PAIRWISE)
    toks = [set(t.lower().split()) for t in sample]
    hits = 0
    for i, a in enumerate(toks):
        if not a:
            continue
        for j, b in enumerate(toks):
            if i == j or not b:
                continue
            inter = len(a & b)
            if inter and inter / len(a | b) >= NEAR_DUP_JACCARD:
                hits += 1
                break
    return hits / len(sample)


def _herdan_c(texts):
    """Vocabulary richness: log(types) / log(tokens).

    Length-normalised, unlike a raw type-token ratio, so it does not drift
    simply because one client sent more requests. A client working from a
    narrow generated vocabulary scores low.
    """
    tokens = [w for t in texts for w in t.lower().split()]
    if len(tokens) < 2:
        return 0.0
    types = len(set(tokens))
    return math.log(max(types, 2)) / math.log(len(tokens))


def _token_entropy_norm(texts):
    """Shannon entropy of the token distribution, divided by its maximum.

    Uniform word salad approaches 1.0; heavily templated traffic sits low.
    Normalising by log(vocab) removes the dependence on vocabulary size.
    """
    tokens = [w for t in texts for w in t.lower().split()]
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    if len(counts) < 2:
        return 0.0
    total = len(tokens)
    h = -sum((c / total) * math.log(c / total) for c in counts.values())
    return h / math.log(len(counts))


def _template_share(texts):
    """Share of queries sharing the single most common structural skeleton.

    The skeleton is (token count, first token, last token) -- crude, but it
    catches grid enumeration, where thousands of queries differ only in a slot.
    """
    if not texts:
        return 0.0
    shapes = Counter()
    for t in texts:
        w = t.lower().split()
        shapes[(len(w), w[0] if w else "", w[-1] if w else "")] += 1
    return shapes.most_common(1)[0][1] / len(texts)


# --- Timing ----------------------------------------------------------------

def _iat_burstiness(timestamps):
    """Burstiness coefficient B = (sd - mean) / (sd + mean) of inter-arrivals.

    Ranges from -1 (perfectly regular, i.e. a metronome) through 0 (Poisson)
    to +1 (highly bursty). Humans work in bursts with idle gaps and sit well
    above zero; an unjittered script sits near -1.

    Note this is rate-independent by construction: scaling every gap by a
    constant leaves B unchanged, so throttling alone does not disguise a
    machine. Adding random jitter does, which is why it is only one of ten
    features and cannot flag a client on its own.
    """
    ts = sorted(timestamps)
    if len(ts) < 3:
        return 0.0
    gaps = [b - a for a, b in zip(ts, ts[1:], strict=False) if b - a >= 0]
    if len(gaps) < 2:
        return 0.0
    m, s = _mean(gaps), _std(gaps)
    if m + s == 0:
        return 0.0
    return (s - m) / (s + m)


# --- Model response --------------------------------------------------------

def _label_balance(labels):
    """Distance from an even label split, in [0, 0.5].

    A client sweeping the input space tends toward whatever the model's prior
    favours; genuine opinion traffic is usually mixed but rarely perfectly so.
    """
    if not labels:
        return 0.0
    counts = Counter(labels)
    top = counts.most_common(1)[0][1]
    return abs(top / len(labels) - 0.5)


# Cap on the wide-context list edit_neighbour_rate compares pairwise. Measured:
# on synthetic benchmark traffic (a small reused vocabulary, so many pairs pass
# the word-overlap prefilter below and reach the expensive comparison), scoring
# 500k requests went from 21.6s to 175s after this signal was added. Real text
# has a far richer vocabulary and did not show this; the cap exists so a small,
# repetitive vocabulary cannot degrade the detector regardless.
MAX_NEIGHBOUR_CONTEXT = 45


def _edit_neighbour_rate(texts, rng=None):
    """Share of queries that have a different-but-close query among the others.

    Identical queries do not count: exact repeats are what customers re-asking
    produce and exact_dup_rate already covers them. This counts a query and an
    EDITED copy of it, which is what probing the decision boundary produces.

    Every pair is compared, so it still works when an attacker reuses a few
    seeds heavily. Two prefilters skip almost every unrelated pair before the
    slower sequence comparison runs: a length-ratio bound, and a word-Jaccard
    bound that is mathematically tighter than it looks -- two sequences whose
    shared-word fraction is below the target ratio cannot reach that ratio on
    SequenceMatcher either, since matched blocks can only be built from shared
    words.
    """
    n = len(texts)
    if n < 2:
        return 0.0
    if n > MAX_NEIGHBOUR_CONTEXT and rng is not None:
        texts = rng.sample(texts, MAX_NEIGHBOUR_CONTEXT)
        n = MAX_NEIGHBOUR_CONTEXT
    words = [t.lower().split() for t in texts]
    norm = [" ".join(w) for w in words]
    sets = [frozenset(w) for w in words]
    lens = [len(w) for w in words]
    linked = set()
    for i in range(n):
        for j in range(i + 1, n):
            if i in linked and j in linked:
                continue
            total = lens[i] + lens[j]
            if not total or norm[i] == norm[j]:
                continue
            if 2 * min(lens[i], lens[j]) < EDIT_NEIGHBOUR_RATIO * total:
                continue  # too different in length to reach the ratio
            if 2 * len(sets[i] & sets[j]) < EDIT_NEIGHBOUR_RATIO * total:
                continue  # too few shared words to reach the ratio
            if SequenceMatcher(None, words[i], words[j], autojunk=False).ratio() \
                    >= EDIT_NEIGHBOUR_RATIO:
                linked.add(i)
                linked.add(j)
    return len(linked) / n


def compute_features(rows, rng=None, wide=None):
    """Feature vector for one client's requests. Rows are parsed log lines.

    Ten signals read `rows`, the window being scored. edit_neighbour_rate reads
    `wide` (the window plus earlier requests) when given, and `rows` otherwise.
    """
    texts = [r["input"] for r in rows]
    confs = sorted(float(r["confidence"]) for r in rows)
    lengths = [len(t) for t in texts]

    p10 = confs[max(0, int(0.10 * len(confs)) - 1)] if confs else 0.0
    mean_len = _mean(lengths)

    return {
        "exact_dup_rate": 1.0 - (len(set(texts)) / len(texts)) if texts else 0.0,
        "near_dup_rate": _near_dup_rate(texts, rng),
        "herdan_c": _herdan_c(texts),
        "token_entropy_norm": _token_entropy_norm(texts),
        "len_cv": (_std(lengths) / mean_len) if mean_len else 0.0,
        "template_share": _template_share(texts),
        "low_conf_rate": sum(c < 0.9 for c in confs) / len(confs) if confs else 0.0,
        "conf_p10": p10,
        "iat_burstiness": _iat_burstiness([float(r["ts"]) for r in rows]),
        "label_balance": _label_balance([r["predicted_label"] for r in rows]),
        "edit_neighbour_rate": _edit_neighbour_rate(
            [r["input"] for r in (wide if wide is not None else rows)], rng),
    }


REQUIRED_KEYS = frozenset({"ts", "api_key", "input", "predicted_label", "confidence"})


def parse_row(line):
    """One log line as a dict, or None if it is blank, corrupt or incomplete."""
    line = line.strip()
    if not line:
        return None
    try:
        r = json.loads(line)
    except ValueError:
        return None
    if isinstance(r, dict) and REQUIRED_KEYS <= r.keys():
        return r
    return None


def load_log(path):
    """Parse a JSONL request log, skipping lines a tail may have caught mid-write."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            r = parse_row(line)
            if r is not None:
                rows.append(r)
    return rows


def group_by_key(rows):
    """Split parsed rows by API key, each sorted by timestamp."""
    out = {}
    for r in rows:
        out.setdefault(r["api_key"], []).append(r)
    for k in out:
        out[k].sort(key=lambda r: float(r["ts"]))
    return out


def windows(rows, size, stride):
    """Consecutive full-size request windows.

    Partial windows are dropped deliberately. The baseline is fitted on
    windows of exactly `size`, and several features -- burstiness above all --
    are not comparable across window lengths: measured live, a client with 12
    requests in flight scored z=37 on iat_burstiness and settled to z=10 once
    the window filled. Scoring a partial window against a full-window baseline
    manufactures false positives, so a client with fewer than `size` requests
    is reported as insufficient rather than guessed at.
    """
    if len(rows) < size:
        return []
    return [rows[i:i + size] for i in range(0, len(rows) - size + 1, stride)]


def windows_with_context(rows, size, stride, extra=WIDE_EXTRA):
    """The same windows as windows(), each paired with a wider span of history.

    Returns (window, wide) pairs. `wide` is the window plus up to `extra`
    requests before it, so a client's first windows simply have less history.
    Calibration and scoring both build them this way, which keeps the
    baseline and the scores comparable.
    """
    if len(rows) < size:
        return []
    return [(rows[i:i + size], rows[max(0, i - extra):i + size])
            for i in range(0, len(rows) - size + 1, stride)]
