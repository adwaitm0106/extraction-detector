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

import math
from collections import Counter

# Two queries count as near-duplicates above this token-overlap (Jaccard).
# Fixed a priori, not tuned: 0.6 means "most words shared".
NEAR_DUP_JACCARD = 0.6

# Cap on pairwise comparisons. Near-duplicate detection is O(n^2); above this
# many requests a random sample gives the same ratio far more cheaply.
MAX_PAIRWISE = 400

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
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
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


def compute_features(rows, rng=None):
    """Feature vector for one client's requests. Rows are parsed log lines."""
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
    }


def load_log(path):
    """Parse a JSONL request log, skipping lines a tail may have caught mid-write."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = __import__("json").loads(line)
                if {"ts", "api_key", "input", "predicted_label", "confidence"} <= r.keys():
                    rows.append(r)
            except ValueError:
                continue
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
