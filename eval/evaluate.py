"""Score a labelled log and report a confusion matrix.

Ground truth comes from the API key prefix, which is set by the traffic
generator: keys naming an attacker profile are positives, everything else is
negative. Keeping the label in the key rather than in the payload means the
detector never sees it -- it reads the same log an operator would.

Usage:
    python eval/evaluate.py --log data/logs/requests.jsonl \\
        --thresholds thresholds.json --attack-prefix atk- evade-
"""

import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "detector"))

import json  # noqa: E402

from features import group_by_key, load_log  # noqa: E402
from score import score_client  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True)
    p.add_argument("--thresholds", default="thresholds.json")
    p.add_argument("--attack-prefix", nargs="+", default=["atk-", "attacker"],
                   help="key prefixes that are ground-truth attackers")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        print("No baseline at %s -- calibrate first." % args.thresholds)
        return 2
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)

    rows = []
    for path in args.log:
        rows.extend(load_log(path))
    if not rows:
        print("No usable log lines.")
        return 2

    rng = random.Random(args.seed)
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for key, client_rows in sorted(group_by_key(rows).items()):
        r = score_client(client_rows, cal["features"], cal["window"],
                         cal["stride"], rng)
        if not r:
            continue
        truth = any(key.startswith(pre) for pre in args.attack_prefix)
        predicted = r["verdict"] == "ATTACK"
        if truth and predicted:
            tp += 1
        elif truth and not predicted:
            fn += 1
            misses.append(key)
        elif not truth and predicted:
            fp += 1
            false_alarms.append(key)
        else:
            tn += 1

    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    print("clients evaluated: %d\n" % total)
    print("                 predicted")
    print("               attack  benign")
    print("actual attack  %6d  %6d" % (tp, fn))
    print("actual benign  %6d  %6d" % (fp, tn))
    print("\nprecision %.3f   recall %.3f   f1 %.3f" % (prec, rec, f1))
    if misses:
        print("missed attackers: %s" % ", ".join(misses))
    if false_alarms:
        print("false alarms:     %s" % ", ".join(false_alarms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
