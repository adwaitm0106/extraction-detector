"""Cross-key correlation: find extraction campaigns split across API keys.

Per-key detection has an obvious and cheap evasion -- buy K keys and send each
a modest slice of the campaign. Every member looks like an ordinary client;
the attack exists only in aggregate.

This module closes that gap in two stages, and **requires both** before
calling anything a campaign:

1. **Linkage.** Compare every pair of keys on four similarity measures and
   link the pair if it is far more similar than benign pairs typically are.
   Connected components of the resulting graph are candidate campaigns.

2. **Pooled anomaly.** Merge a candidate's traffic and score the union with
   the ordinary per-key detector. A campaign is confirmed only if the pool
   looks anomalous.

Requiring both matters. Two support agents at the same company share
vocabulary and working hours, so linkage alone would flag them; their pooled
traffic still looks like ordinary opinion text, so the second stage clears
them. Conversely a pool that looks odd but whose members share nothing is
more likely to be several unrelated oddities than one coordinated actor.

The same anti-overfitting discipline applies as in calibrate.py: the pair
baseline is fitted on **benign traffic only**, using median and MAD, and the
cutoffs are the same fixed constants used for per-key scoring.

Usage:
    python detector/campaign.py --log data/logs/requests.jsonl \\
        --thresholds thresholds.json
"""

import argparse
import json
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import (  # noqa: E402
    NEAR_DUP_JACCARD,
    group_by_key,
    load_log,
)
from score import MIN_FLAGS, Z_FLAG, score_client  # noqa: E402

PAIR_FEATURES = ("vocab_jaccard", "skeleton_jaccard", "cross_dup_rate", "time_overlap")

# Cap on queries compared per key. Cross-key duplicate search is O(n*m) per
# pair and O(k^2) pairs; sampling keeps a large log tractable without
# changing the ratios being estimated.
MAX_QUERIES_PER_KEY = 200


def _vocab(rows):
    return {w for r in rows for w in r["input"].lower().split()}


def _skeletons(rows):
    """Structural fingerprints: (token count, first token, last token)."""
    out = Counter()
    for r in rows:
        w = r["input"].lower().split()
        out[(len(w), w[0] if w else "", w[-1] if w else "")] += 1
    return set(out)


def _jaccard(a, b):
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _cross_dup_rate(rows_a, rows_b, rng):
    """Share of one key's queries that closely match a query from the other.

    A campaign that partitions a template grid produces queries that are not
    identical across members but are structurally near-identical, which is
    what this measures. Symmetric by taking the mean of both directions.
    """
    def sample(rows):
        texts = [r["input"] for r in rows]
        if len(texts) > MAX_QUERIES_PER_KEY:
            texts = rng.sample(texts, MAX_QUERIES_PER_KEY)
        return [set(t.lower().split()) for t in texts]

    A, B = sample(rows_a), sample(rows_b)
    if not A or not B:
        return 0.0

    def hits(X, Y):
        n = 0
        for a in X:
            if not a:
                continue
            for b in Y:
                if b and len(a & b) / len(a | b) >= NEAR_DUP_JACCARD:
                    n += 1
                    break
        return n / len(X)

    return (hits(A, B) + hits(B, A)) / 2.0


def _time_overlap(rows_a, rows_b):
    """Jaccard of the two keys' active time spans.

    Weak on its own -- most clients are active during the day -- but a
    campaign run in one sitting overlaps almost perfectly, and it costs
    nothing to compute.
    """
    a0, a1 = min(float(r["ts"]) for r in rows_a), max(float(r["ts"]) for r in rows_a)
    b0, b1 = min(float(r["ts"]) for r in rows_b), max(float(r["ts"]) for r in rows_b)
    inter = max(0.0, min(a1, b1) - max(a0, b0))
    union = max(a1, b1) - min(a0, b0)
    return inter / union if union > 0 else 0.0


def pair_features(rows_a, rows_b, rng):
    return {
        "vocab_jaccard": _jaccard(_vocab(rows_a), _vocab(rows_b)),
        "skeleton_jaccard": _jaccard(_skeletons(rows_a), _skeletons(rows_b)),
        "cross_dup_rate": _cross_dup_rate(rows_a, rows_b, rng),
        "time_overlap": _time_overlap(rows_a, rows_b),
    }


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return 0.0
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def fit_pair_baseline(by_key, rng, min_scale=0.02):
    """Median and MAD of each pair measure across all benign key pairs.

    min_scale floors the spread the same way the per-key baseline does: with
    few benign clients the MAD can collapse to zero and turn ordinary
    variation into an enormous z-score.
    """
    keys = sorted(by_key)
    samples = []
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            samples.append(pair_features(by_key[a], by_key[b], rng))
    if len(samples) < 3:
        return None
    baseline = {}
    for name in PAIR_FEATURES:
        vals = [s[name] for s in samples]
        centre = _median(vals)
        mad = _median([abs(v - centre) for v in vals])
        baseline[name] = {"centre": centre,
                          "scale": max(mad * 1.4826, min_scale)}
    return {"features": baseline, "n_pairs": len(samples), "n_clients": len(keys)}


def link_pairs(by_key, baseline, rng):
    """Pairs whose similarity is far above the benign norm.

    One-sided: only *excess* similarity is evidence of a shared source. Two
    keys being unusually dissimilar means nothing.
    """
    keys = sorted(by_key)
    links = []
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            feats = pair_features(by_key[a], by_key[b], rng)
            zs = {}
            for name in PAIR_FEATURES:
                ref = baseline[name]
                zs[name] = max(0.0, (feats[name] - ref["centre"]) / ref["scale"])
            flags = [n for n, z in zs.items() if z >= Z_FLAG]
            if len(flags) >= MIN_FLAGS:
                links.append({"a": a, "b": b, "flags": flags,
                              "z": {k: round(v, 2) for k, v in zs.items()}})
    return links


def components(keys, links):
    """Connected components over the link graph -- one per candidate campaign."""
    parent = {k: k for k in keys}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for ln in links:
        ra, rb = find(ln["a"]), find(ln["b"])
        if ra != rb:
            parent[ra] = rb
    groups = {}
    for k in keys:
        groups.setdefault(find(k), []).append(k)
    return [sorted(v) for v in groups.values() if len(v) > 1]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True, help="log to analyse")
    p.add_argument("--benign-log", nargs="+",
                   help="benign-only log for the pair baseline; defaults to the "
                        "calibration log recorded in --thresholds")
    p.add_argument("--thresholds", default="thresholds.json")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        print("No baseline at %s -- run detector/calibrate.py first." % args.thresholds)
        return 2
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)

    rng = random.Random(args.seed)

    # --- Pair baseline. Benign-only, exactly as for the per-key baseline. ---
    benign_paths = args.benign_log or cal.get("source_logs")
    if not benign_paths:
        print("No benign log given. Pass --benign-log pointing at benign-only "
              "traffic; the pair baseline must never see an attack sample.")
        return 2
    benign_rows = []
    for path in benign_paths:
        benign_rows.extend(load_log(path))
    pair_cal = fit_pair_baseline(group_by_key(benign_rows), rng)
    if pair_cal is None:
        print("Need at least 3 benign key pairs (3 clients) to fit a pair "
              "baseline; found too few.")
        return 2

    rows = []
    for path in args.log:
        rows.extend(load_log(path))
    by_key = group_by_key(rows)

    links = link_pairs(by_key, pair_cal["features"], rng)
    groups = components(sorted(by_key), links)

    print("pair baseline: %d benign pairs from %d clients" %
          (pair_cal["n_pairs"], pair_cal["n_clients"]))
    print("linkage: pair flagged at z >= %.1f on >= %d measures\n" % (Z_FLAG, MIN_FLAGS))

    # --- Per-key verdicts first: the point is that campaign members pass. ---
    per_key = {}
    for key, client_rows in by_key.items():
        r = score_client(client_rows, cal["features"], cal["window"],
                         cal["stride"], rng)
        per_key[key] = r["verdict"] if r else "insufficient"

    if not groups:
        print("No linked groups found.")
    for g in groups:
        pooled_rows = sorted((r for k in g for r in by_key[k]),
                             key=lambda r: float(r["ts"]))
        pooled = score_client(pooled_rows, cal["features"], cal["window"],
                              cal["stride"], rng)
        individually = [per_key.get(k, "?") for k in g]
        confirmed = pooled is not None and pooled["verdict"] == "ATTACK"

        print("group of %d: %s" % (len(g), ", ".join(g)))
        print("  members individually : %s" % ", ".join(individually))
        ev = sorted({f for ln in links
                     if ln["a"] in g and ln["b"] in g for f in ln["flags"]})
        print("  linked on            : %s" % ", ".join(ev))
        if pooled:
            top = sorted(pooled["flags"], key=lambda n: -pooled["z"][n])[:3]
            print("  pooled (%d requests) : %d flags -- %s"
                  % (len(pooled_rows), pooled["n_flags"],
                     ", ".join("%s(%.1f)" % (n, pooled["z"][n]) for n in top) or "none"))
        print("  VERDICT              : %s\n"
              % ("CAMPAIGN" if confirmed else "linked but pooled traffic looks normal"))

    hidden = [g for g in groups
              if all(per_key.get(k) != "ATTACK" for k in g)]
    if hidden:
        print("%d group(s) contained no individually-flagged member -- these are "
              "the ones per-key detection alone would have missed." % len(hidden))
    return 0


if __name__ == "__main__":
    sys.exit(main())
