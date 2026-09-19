"""Does blocking the attacker actually protect the model?

Detection is only worth something if it stops the theft. This script measures
that directly by playing the attacker:

  1. Harvest: send natural-looking queries to the victim and keep the
     (input, label) pairs it answers with. That is the attacker's training set.
  2. Train a copy: fit a small student classifier on the harvested pairs.
  3. Measure fidelity: how often does the copy agree with the victim on
     sentences neither has seen?

It runs the harvest twice. Once with nobody watching, and once with the
detector enforcing in the loop, so the attacker gets cut off with HTTP 429 the
moment it is flagged. The difference in the copy's fidelity is the value of
the detector, in the attacker's own currency.

The student is a naive Bayes classifier written here in plain Python, so this
needs nothing beyond what the API already needs. It is a weak student on
purpose: the point is the *gap* between the two harvests, not the absolute
quality of the copy.

Usage (API running, thresholds.json present):
    python eval/steal.py
    python eval/steal.py --n 500 --heldout 300
"""

import argparse
import json
import math
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "traffic"))
sys.path.insert(0, os.path.join(ROOT, "detector"))

from corpus import benign_query, natural_query  # noqa: E402
from features import group_by_key, load_log  # noqa: E402
from score import score_client, write_blocklist  # noqa: E402

# --- Talking to the victim ---------------------------------------------------

def call(base, key, text, timeout=30):
    req = urllib.request.Request(
        base.rstrip("/") + "/predict",
        data=json.dumps({"input": text}).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-API-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read()).get("label")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return -1, None


def harvest(base, key, n, rate, rng, enforce=None, log_path=None, cal=None,
            check_every=5):
    """Query the victim n times and keep every (input, label) it hands back.

    With `enforce`, the real detector is run against the real log every few
    requests and writes the real blocklist. The API then answers 429 and the
    harvest stops. Nothing here is simulated; it is the same enforcement path
    the demo uses.
    """
    pairs = []
    interval = 1.0 / rate
    for i in range(n):
        text = natural_query(i)
        status, label = call(base, key, text)
        if status == 429:
            return pairs, i, True
        if status == 200 and label:
            pairs.append((text, label))
        if enforce and (i + 1) % check_every == 0:
            rows = group_by_key(load_log(log_path)).get(key, [])
            r = score_client(rows, cal["features"], cal["window"], cal["stride"], rng)
            if r and r["verdict"] == "ATTACK":
                write_blocklist(enforce, {key: r})
        time.sleep(rng.expovariate(1.0 / interval))
    return pairs, n, False


# --- The attacker's copy -----------------------------------------------------

_TOKEN = re.compile(r"[a-z']+")


def tokens(text):
    return _TOKEN.findall(text.lower())


class NaiveBayes:
    """Multinomial naive Bayes over words, Laplace smoothed. Deliberately simple."""

    def __init__(self, alpha=1.0):
        self.alpha = alpha
        self.prior = {}
        self.counts = {}
        self.totals = {}
        self.vocab = set()

    def fit(self, pairs):
        labels = Counter(label for _, label in pairs)
        n = sum(labels.values())
        self.prior = {c: math.log(k / n) for c, k in labels.items()}
        self.counts = {c: Counter() for c in labels}
        self.totals = {c: 0 for c in labels}
        self.vocab = set()
        for text, label in pairs:
            for w in tokens(text):
                self.counts[label][w] += 1
                self.totals[label] += 1
                self.vocab.add(w)
        return self

    def predict(self, text):
        if not self.prior:
            return None
        v = len(self.vocab)
        best, best_lp = None, None
        for c, lp in self.prior.items():
            for w in tokens(text):
                if w in self.vocab:
                    lp += math.log((self.counts[c][w] + self.alpha)
                                   / (self.totals[c] + self.alpha * v))
            if best_lp is None or lp > best_lp:
                best, best_lp = c, lp
        return best


def fidelity(student, heldout):
    """Share of held-out sentences on which the copy agrees with the victim."""
    if not heldout:
        return 0.0
    hits = sum(student.predict(text) == label for text, label in heldout)
    return hits / len(heldout)


# --- Main --------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--n", type=int, default=500, help="queries the unthrottled attacker sends")
    p.add_argument("--heldout", type=int, default=300, help="size of the held-out test set")
    p.add_argument("--rate", type=float, default=8.0, help="attacker queries/sec (Poisson)")
    p.add_argument("--thresholds", default=os.path.join(ROOT, "thresholds.json"))
    p.add_argument("--log", default=os.path.join(ROOT, "data", "logs", "requests.jsonl"))
    p.add_argument("--blocklist", default=os.path.join(ROOT, "blocked.json"))
    p.add_argument("--out-fig", default=os.path.join(ROOT, "eval", "figures",
                                                     "stolen_model_fidelity.png"))
    p.add_argument("--out-json", default=os.path.join(ROOT, "eval", "figures",
                                                      "stolen_model_fidelity.json"))
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()

    try:
        with urllib.request.urlopen(args.base_url.rstrip("/") + "/health", timeout=5) as r:
            if not json.loads(r.read()).get("model_loaded"):
                print("API is up but the model is not loaded yet.")
                return 2
    except Exception as e:
        print("Cannot reach the API at %s: %s" % (args.base_url, e))
        return 2
    if not os.path.exists(args.thresholds):
        print("No baseline at %s. Calibrate first." % args.thresholds)
        return 2
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    if os.path.exists(args.blocklist):
        os.remove(args.blocklist)  # a stale block would end the harvest at query 1

    # --- Held-out set: sentences neither side trains on, labelled by the victim.
    print("labelling %d held-out sentences with the victim..." % args.heldout)
    ho_rng = random.Random(args.seed + 1000)
    heldout = []
    seen = set()
    while len(heldout) < args.heldout:
        text = benign_query(ho_rng)
        if text in seen:
            continue
        seen.add(text)
        status, label = call(args.base_url, "eval-oracle", text)
        if status == 200 and label:
            heldout.append((text, label))
    majority = Counter(lbl for _, lbl in heldout).most_common(1)[0][1] / len(heldout)
    print("  done. always-guess-majority baseline: %.1f%% agreement\n" % (100 * majority))

    # --- Run 1: nobody watching. ---
    print("run 1: attacker harvests %d queries, no enforcement..." % args.n)
    t0 = time.time()
    pairs_free, sent_free, _ = harvest(args.base_url, "thief-unwatched", args.n,
                                       args.rate, random.Random(args.seed))
    print("  harvested %d pairs in %.0fs\n" % (len(pairs_free), time.time() - t0))

    # --- Run 2: detector enforcing in the loop. ---
    print("run 2: same attacker, detector enforcing (429 once flagged)...")
    t0 = time.time()
    pairs_cut, sent_cut, was_cut = harvest(
        args.base_url, "thief-blocked", args.n, args.rate, random.Random(args.seed),
        enforce=args.blocklist, log_path=args.log, cal=cal)
    if was_cut:
        print("  cut off after %d queries; %d usable pairs harvested (%.0fs)\n"
              % (sent_cut, len(pairs_cut), time.time() - t0))
    else:
        print("  NOT cut off: attacker completed all %d queries (%.0fs)\n"
              % (sent_cut, time.time() - t0))

    # --- Learning curve on the free harvest, with the cut-off point marked. ---
    sizes = sorted({s for s in (10, 20, 30, 40, 50, 75, 100, 150, 200, 300, 400, 500)
                    if s <= len(pairs_free)} | {len(pairs_cut), len(pairs_free)})
    curve = []
    for s in sizes:
        if s == 0:
            curve.append((s, majority))
            continue
        student = NaiveBayes().fit(pairs_free[:s])
        curve.append((s, fidelity(student, heldout)))

    fid_cut = fidelity(NaiveBayes().fit(pairs_cut), heldout) if pairs_cut else majority
    fid_free = fidelity(NaiveBayes().fit(pairs_free), heldout)

    print("%-22s %10s" % ("harvested pairs", "fidelity"))
    print("-" * 34)
    for s, f in curve:
        mark = "  <- where enforcement cut the attacker off" if s == len(pairs_cut) else ""
        print("%-22d %9.1f%%%s" % (s, 100 * f, mark))
    print()
    print("copy trained WITHOUT enforcement : %4d pairs -> %.1f%% agreement with the victim"
          % (len(pairs_free), 100 * fid_free))
    print("copy trained WITH enforcement    : %4d pairs -> %.1f%% agreement with the victim"
          % (len(pairs_cut), 100 * fid_cut))
    print("always guess the majority label  :         -> %.1f%%" % (100 * majority))

    results = {
        "heldout": len(heldout), "majority_baseline": majority,
        "unwatched": {"pairs": len(pairs_free), "fidelity": fid_free},
        "enforced": {"pairs": len(pairs_cut), "queries_before_429": sent_cut,
                     "was_cut_off": was_cut, "fidelity": fid_cut},
        "curve": [{"pairs": s, "fidelity": f} for s, f in curve],
    }
    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    # --- Chart, if matplotlib is around. Optional on purpose. ---
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        xs = [s for s, _ in curve]
        ys = [100 * f for _, f in curve]
        fig, ax = plt.subplots(figsize=(7.5, 4.2))
        ax.plot(xs, ys, marker="o", color="#b3261e", label="attacker's copy, no enforcement")
        ax.axhline(100 * majority, color="#888", linestyle=":", linewidth=1,
                   label="always guess majority (%.0f%%)" % (100 * majority))
        if pairs_cut:
            ax.axvline(len(pairs_cut), color="#1f6d3f", linestyle="--", linewidth=1.5)
            ax.plot([len(pairs_cut)], [100 * fid_cut], marker="s", color="#1f6d3f",
                    markersize=8, label="with enforcement: cut off here (%.0f%%)" % (100 * fid_cut))
        ax.set_xscale("log")
        ax.set_xlabel("query/label pairs the attacker harvested (log scale)")
        ax.set_ylabel("copy agrees with victim (%)")
        ax.set_ylim(min(40, min(ys) - 5), 101)
        ax.set_title("How good is the stolen copy, versus how much the attacker got to harvest",
                     fontsize=10)
        ax.legend(fontsize=8, loc="lower right")
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        fig.tight_layout()
        fig.savefig(args.out_fig, dpi=150)
        print("\nwrote %s" % args.out_fig)
    except ImportError:
        print("\n(matplotlib not installed; skipped the chart)")

    # Leave nothing blocked behind.
    if os.path.exists(args.blocklist):
        os.remove(args.blocklist)
    return 0


if __name__ == "__main__":
    sys.exit(main())
