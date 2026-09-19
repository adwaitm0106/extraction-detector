"""Measure what each defence is worth against a real-text harvester.

Replays the pairs collected by eval/harvest_real.py under each defence, trains
the attacker's stolen copy on whatever the defence let through, and scores the
copy by how often it agrees with the victim on held-out real text it never
trained on.

Defences:
    response mode   full, rounded or label, via api/defences.shape_response,
                    the same function the API itself calls
    query budget    a cap on served requests per API key, against an attacker
                    with one key and against one with several

Students, both TF-IDF over word unigrams and bigrams into logistic regression:
    hard   trained on labels only
    soft   each example weighted by the victim's confidence, when the response
           includes one; this is how an attacker exploits confidence scores

Hyperparameters are fixed up front and never tuned on the held-out set.

    python eval/defend_real.py

Writes eval/results/defences_real.json, eval/results/defences_real.md and
eval/figures/defence_budget_fidelity.png.
"""

import argparse
import json
import os
import random
import statistics
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "api"))

from defences import RESPONSE_MODES, shape_response  # noqa: E402

PAIRS = os.path.join(ROOT, "data", "logs", "steal_real_pairs.jsonl")
RESULTS = os.path.join(HERE, "results")
FIGURE = os.path.join(HERE, "figures", "defence_budget_fidelity.png")

SIZES = (25, 50, 100, 200, 400, 800, 1600)
REPEATS = 5
C = 4.0
FLIP = {"POSITIVE": "NEGATIVE", "NEGATIVE": "POSITIVE"}


def load_pairs(path):
    heldout, harvest = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                (heldout if r["set"] == "heldout" else harvest).append(r)
    harvest.sort(key=lambda r: r["i"])
    return heldout, harvest


def train(texts, labels, confs, soft):
    """Fit a student; returns a function mapping texts to predicted labels."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    rows_t, rows_y, rows_w = [], [], []
    for t, y, p in zip(texts, labels, confs, strict=True):
        p = 1.0 if (not soft or p is None) else float(p)
        rows_t.append(t)
        rows_y.append(y)
        rows_w.append(p)
        if p < 1.0:
            # The rest of the probability mass belongs to the other label.
            rows_t.append(t)
            rows_y.append(FLIP[y])
            rows_w.append(1.0 - p)

    if len(set(rows_y)) < 2:
        only = rows_y[0]
        return lambda xs: [only] * len(xs)
    vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    clf = LogisticRegression(C=C, max_iter=2000)
    clf.fit(vec.fit_transform(rows_t), rows_y, sample_weight=rows_w)
    return lambda xs: list(clf.predict(vec.transform(xs)))


def fidelity(predict, heldout):
    texts = [r["text"] for r in heldout]
    preds = predict(texts)
    return sum(p == r["label"] for p, r in zip(preds, heldout, strict=True)) / len(heldout)


def shaped(pairs, mode):
    """What the attacker actually saw for these pairs under a response mode."""
    texts, labels, confs = [], [], []
    for r in pairs:
        s = shape_response(r["label"], r["confidence"], mode)
        texts.append(r["text"])
        labels.append(s["label"])
        confs.append(s.get("confidence"))
    return texts, labels, confs


def pct(x):
    return "%.1f%%" % (100 * x)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pairs", default=PAIRS)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    try:
        import sklearn  # noqa: F401
    except ImportError:
        raise SystemExit("scikit-learn is not installed. Run:\n"
                         "  .venv/Scripts/python.exe -m pip install -r eval/requirements.txt") from None
    if not os.path.exists(args.pairs):
        raise SystemExit("No pairs at %s. Run eval/harvest_real.py first." % args.pairs)

    heldout, harvest = load_pairs(args.pairs)
    n = len(harvest)
    majority_label, majority_n = Counter(r["label"] for r in heldout).most_common(1)[0]
    majority = majority_n / len(heldout)
    print("held-out %d texts, harvest %d pairs, always guessing %s scores %s"
          % (len(heldout), n, majority_label, pct(majority)))

    # --- 1. response modes, attacker keeps every pair ---
    modes = {}
    for mode in RESPONSE_MODES:
        t, y, c = shaped(harvest, mode)
        modes[mode] = {"hard": fidelity(train(t, y, c, soft=False), heldout),
                       "soft": fidelity(train(t, y, c, soft=True), heldout)}
        print("  mode %-8s hard %s  soft %s" % (mode, pct(modes[mode]["hard"]),
                                               pct(modes[mode]["soft"])))

    # --- 2. how the copy improves with more pairs; a budget picks a point ---
    cache = {}

    def at_size(size):
        size = min(size, n)
        if size in cache:
            return cache[size]
        runs = {"hard": [], "soft": []}
        repeats = 1 if size == n else REPEATS
        for rep in range(repeats):
            rng = random.Random(args.seed * 1000 + rep * 7919 + size)
            sample = harvest if size == n else rng.sample(harvest, size)
            t, y, c = shaped(sample, "full")
            runs["hard"].append(fidelity(train(t, y, c, soft=False), heldout))
            runs["soft"].append(fidelity(train(t, y, c, soft=True), heldout))
        cache[size] = {k: {"mean": statistics.mean(v),
                           "std": statistics.stdev(v) if len(v) > 1 else 0.0}
                       for k, v in runs.items()}
        return cache[size]

    curve = []
    for size in sorted(set(SIZES) | {n}):
        if size > n:
            continue
        r = at_size(size)
        curve.append({"pairs": size, **r})
        print("  %5d pairs  hard %s (+/- %.1f)  soft %s (+/- %.1f)" % (
            size, pct(r["hard"]["mean"]), 100 * r["hard"]["std"],
            pct(r["soft"]["mean"]), 100 * r["soft"]["std"]))

    # --- 3. a per-key budget against an attacker holding several keys ---
    splits = []
    for budget in (50, 100, 200):
        for keys in (1, 5, 20):
            got = min(budget * keys, n)
            r = at_size(got)
            splits.append({"budget": budget, "keys": keys, "pairs": got,
                           "fidelity": r["soft"]["mean"]})

    results = {"heldout": len(heldout), "harvest": n,
               "majority_baseline": majority, "students_C": C,
               "response_modes": modes, "curve": curve, "budget_vs_keys": splits}
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "defences_real.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    md = ["Stolen copy agreement with the victim on %d held-out real texts. Always "
          "guessing the most common label scores %s." % (len(heldout), pct(majority)), "",
          "**Response modes** (attacker keeps all %d pairs)" % n, "",
          "| Response mode | Copy trained on labels | Copy weighted by confidence |",
          "|---|---|---|"]
    for mode in RESPONSE_MODES:
        md.append("| `%s` | %s | %s |" % (mode, pct(modes[mode]["hard"]), pct(modes[mode]["soft"])))
    md += ["", "**Pairs harvested** (mean of %d random samples, full responses)" % REPEATS, "",
           "| Pairs | Copy trained on labels | Copy weighted by confidence |", "|---|---|---|"]
    for row in curve:
        md.append("| %d | %s (+/- %.1f) | %s (+/- %.1f) |" % (
            row["pairs"], pct(row["hard"]["mean"]), 100 * row["hard"]["std"],
            pct(row["soft"]["mean"]), 100 * row["soft"]["std"]))
    md += ["", "**Per-key budget against an attacker with several keys**", "",
           "| Budget per key | Keys | Pairs collected | Copy agreement |", "|---|---|---|---|"]
    for s in splits:
        md.append("| %d | %d | %d | %s |" % (s["budget"], s["keys"], s["pairs"], pct(s["fidelity"])))
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "defences_real.md"), "w", encoding="utf-8") as fh:
        fh.write(text)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [r["pairs"] for r in curve]
        fig, ax = plt.subplots(figsize=(7.5, 4.2))
        for key, colour, name in (("soft", "#b3261e", "copy weighted by confidence"),
                                  ("hard", "#2f5bd0", "copy trained on labels only")):
            ys = [100 * r[key]["mean"] for r in curve]
            es = [100 * r[key]["std"] for r in curve]
            ax.errorbar(xs, ys, yerr=es, marker="o", color=colour, capsize=3, label=name)
        ax.axhline(100 * majority, color="#888", linestyle=":", linewidth=1,
                   label="always guess %s (%.0f%%)" % (majority_label.lower(), 100 * majority))
        ax.set_xscale("log")
        ax.set_xlabel("query/answer pairs the attacker collected (log scale)")
        ax.set_ylabel("copy agrees with victim (%)")
        ax.set_title("Real-text harvesting: a per-key budget is a point on this curve",
                     fontsize=10)
        ax.legend(fontsize=8, loc="lower right")
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        fig.tight_layout()
        os.makedirs(os.path.dirname(FIGURE), exist_ok=True)
        fig.savefig(FIGURE, dpi=150)
        print("wrote %s" % os.path.relpath(FIGURE, ROOT))
    except ImportError:
        print("(matplotlib not installed; skipped the chart)")

    print()
    print(text)
    print("wrote eval/results/defences_real.json and eval/results/defences_real.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
