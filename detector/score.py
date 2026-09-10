"""Score clients against the benign baseline and flag likely extraction.

The rule is intentionally low-capacity, because a model with more knobs than
this would start fitting the four attack profiles in the generator rather than
extraction in general:

    z_f      = |value - centre| / scale          (robust, two-sided)
    flags    = count of features with z_f >= Z_FLAG
    verdict  = ATTACK if flags >= MIN_FLAGS

Two-sided is the point. The `random` profile pushes token entropy *up*; the
`sweep` profile pushes it *down*. Picking a direction per feature would mean
choosing which attack to catch, using knowledge of the attacks -- exactly the
leak we are trying to avoid. "Unlike normal in either direction" needs no such
knowledge.

Both constants below are fixed a priori, not tuned against results:

    Z_FLAG = 3.5    a deviation this large has probability ~0.0005 per feature
                    under a normal baseline
    MIN_FLAGS = 2   one odd feature is a quirk; two independent ones is a
                    pattern. Requiring two keeps single-feature noise from
                    producing false positives.

Usage:
    python detector/score.py --log data/logs/requests.jsonl \\
        --thresholds thresholds.json
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import (  # noqa: E402
    FEATURE_NAMES,
    compute_features,
    group_by_key,
    load_log,
    windows,
)

Z_FLAG = 3.5
MIN_FLAGS = 2


def score_window(feats, baseline):
    """Per-feature robust z-scores, plus the flag count and mean deviation."""
    zs = {}
    for name in FEATURE_NAMES:
        b = baseline[name]
        zs[name] = abs(feats[name] - b["centre"]) / b["scale"]
    flagged = [n for n, z in zs.items() if z >= Z_FLAG]
    return {
        "z": zs,
        "flags": flagged,
        "n_flags": len(flagged),
        "mean_z": sum(zs.values()) / len(zs),
        "max_z": max(zs.values()),
    }


def score_client(rows, baseline, window, stride, rng):
    """Worst window wins.

    A client is judged on its most anomalous window rather than its average.
    An attacker who sends a thousand innocuous queries around a short probing
    burst should not be able to dilute that burst into the mean.
    """
    results = [
        score_window(compute_features(w, rng), baseline)
        for w in windows(rows, window, stride)
        if len(w) >= 10
    ]
    if not results:
        return None
    worst = max(results, key=lambda r: (r["n_flags"], r["mean_z"]))
    worst["n_windows"] = len(results)
    worst["n_requests"] = len(rows)
    worst["verdict"] = "ATTACK" if worst["n_flags"] >= MIN_FLAGS else "benign"
    return worst


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True)
    p.add_argument("--thresholds", default="thresholds.json")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        print("No baseline at %s -- run detector/calibrate.py on benign traffic "
              "first." % args.thresholds)
        return 2
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    baseline, window, stride = cal["features"], cal["window"], cal["stride"]

    rows = []
    for path in args.log:
        rows.extend(load_log(path))
    if not rows:
        print("No usable log lines found.")
        return 2

    rng = random.Random(args.seed)
    verdicts = {}
    for key, client_rows in sorted(group_by_key(rows).items()):
        r = score_client(client_rows, baseline, window, stride, rng)
        if r:
            verdicts[key] = r

    if args.json:
        print(json.dumps(verdicts, indent=2, sort_keys=True))
        return 0

    print("baseline: %d benign windows, %d clients, window=%d stride=%d"
          % (cal["n_windows"], cal["n_clients"], window, stride))
    print("rule: flag a feature at z >= %.1f; call ATTACK at >= %d flags\n"
          % (Z_FLAG, MIN_FLAGS))
    hdr = "%-20s %6s %6s %7s %8s  %s" % (
        "api_key", "reqs", "wins", "flags", "verdict", "features flagged")
    print(hdr)
    print("-" * (len(hdr) + 14))
    for key, r in sorted(verdicts.items(),
                         key=lambda kv: (-kv[1]["n_flags"], -kv[1]["mean_z"])):
        top = sorted(r["flags"], key=lambda n: -r["z"][n])
        detail = ", ".join("%s(%.1f)" % (n, r["z"][n]) for n in top[:3])
        print("%-20s %6d %6d %7d %8s  %s"
              % (key, r["n_requests"], r["n_windows"], r["n_flags"],
                 r["verdict"], detail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
