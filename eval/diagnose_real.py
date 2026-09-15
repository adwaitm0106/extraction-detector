"""Show why the detector catches some real-text attackers and not others.

Reads the log and baseline written by eval/run_real_experiment.py. For each
group of clients it reports the median value of every signal next to the
baseline centre, then lists each harvest key's strongest deviations. Writes
the same tables to eval/results/real_data_diagnostics.md.

    python eval/diagnose_real.py

Needs no API: it only reads files the experiment already produced.
"""

import json
import os
import random
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from features import FEATURE_NAMES, compute_features, group_by_key, load_log, windows  # noqa: E402
from score import MIN_FLAGS, Z_FLAG, score_client  # noqa: E402

LOGS = os.path.join(ROOT, "data", "logs")
EVAL_LOG = os.path.join(LOGS, "real_eval.jsonl")
THRESHOLDS = os.path.join(LOGS, "real_thresholds.json")
OUT = os.path.join(HERE, "results", "real_data_diagnostics.md")
GROUPS = ("customers (seen)", "customers (unseen)", "probers", "harvesters")


def group_of(key):
    if key.startswith("cust-imdb"):
        return "customers (unseen)"
    if key.startswith("cust-"):
        return "customers (seen)"
    if "probe" in key or "boundary" in key:
        return "probers"
    return "harvesters"


def main():
    for path in (EVAL_LOG, THRESHOLDS):
        if not os.path.exists(path):
            print("Missing %s. Run eval/run_real_experiment.py first." % path)
            return 2
    with open(THRESHOLDS, encoding="utf-8") as fh:
        cal = json.load(fh)
    base = cal["features"]
    by_key = group_by_key(load_log(EVAL_LOG))
    rng = random.Random(0)

    vals = {g: {f: [] for f in FEATURE_NAMES} for g in GROUPS}
    for key, rows in by_key.items():
        for w in windows(rows, cal["window"], cal["stride"]):
            feats = compute_features(w, rng)
            for f in FEATURE_NAMES:
                vals[group_of(key)][f].append(feats[f])

    lines = [
        "Median value of each signal per group, over every full window, next to "
        "the baseline learned from real customers.",
        "",
        "| Signal | Baseline centre | Baseline spread | " + " | ".join(GROUPS) + " |",
        "|---|---|---|" + "---|" * len(GROUPS),
    ]
    for f in FEATURE_NAMES:
        meds = ["%.3f" % statistics.median(vals[g][f]) if vals[g][f] else "n/a"
                for g in GROUPS]
        lines.append("| `%s` | %.3f | %.3f | %s |" % (
            f, base[f]["centre"], base[f]["scale"], " | ".join(meds)))

    lines += [
        "",
        "Strongest deviations for each harvest key. A client is flagged at "
        "z >= %.1f on at least %d signals." % (Z_FLAG, MIN_FLAGS),
        "",
        "| Key | Top three z-scores |",
        "|---|---|",
    ]
    for key in sorted(by_key):
        if group_of(key) != "harvesters":
            continue
        r = score_client(by_key[key], base, cal["window"], cal["stride"], rng)
        if r is None:
            continue
        top = sorted(r["z"].items(), key=lambda kv: -kv[1])[:3]
        lines.append("| `%s` | %s |" % (key, ", ".join("%s %.1f" % kv for kv in top)))

    text = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print("wrote %s" % os.path.relpath(OUT, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
