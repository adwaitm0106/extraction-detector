"""Fit the benign baseline.

This is where overfitting would creep in, so the design is deliberately
constrained:

* **Benign traffic only.** Calibration never sees an attack sample, so the
  detector cannot learn the signature of the four profiles the generator
  happens to implement. It learns what normal looks like; anything unlike
  normal is suspicious, including attacks nobody has written yet.
* **Median and MAD, not mean and standard deviation.** A couple of odd benign
  clients would drag a mean-based baseline toward themselves and mask real
  attacks. The median absolute deviation ignores them.
* **No per-feature weights.** Nothing is fitted except each feature's centre
  and spread -- two numbers per feature, ten features. There is no coefficient
  vector to overfit with.

The flag cutoff itself is a fixed constant in score.py, chosen a priori from
the normal distribution rather than tuned against results.

Operational note -- calibrate per client class
    A median-based baseline describes the *typical* client in its calibration
    set. Mixing human users and service accounts into one baseline makes the
    minority look anomalous: measured here, a legitimate machine-paced
    integration scored 2 flags (ATTACK) against a human-dominated baseline,
    and 0 flags (benign) against a baseline built from service accounts alone.
    Attack recall was unchanged at 6/6 either way.

    So calibrate one baseline per class of client and score each client
    against its own. Adding a handful of service accounts to a human baseline
    does not work: a minority cannot move a median.

Usage:
    python detector/calibrate.py --log data/logs/benign_calib.jsonl \\
        --out thresholds.json
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import (  # noqa: E402
    FEATURE_NAMES,
    PROPORTION_FEATURES,
    compute_features,
    group_by_key,
    load_log,
    windows,
)

# Scale factor making MAD a consistent estimator of sigma for normal data.
MAD_TO_SIGMA = 1.4826

# Floor on spread. Without it, a feature that is constant across the benign
# sample would have MAD 0 and turn any deviation at all into an infinite
# z-score -- a single quirk would flag every client.
#
# For proportions the floor is derived from the window size rather than picked:
# a rate over W requests cannot resolve finer than one request, so 1/W is the
# smallest deviation that can mean anything. For the remaining features, which
# are not proportions, a small epsilon is enough.
MIN_SCALE = 1e-3


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return 0.0
    mid = n // 2
    return xs[mid] if n % 2 else (xs[mid - 1] + xs[mid]) / 2.0


def fit(samples, window):
    """Centre and scale per feature, from a list of benign feature dicts."""
    baseline = {}
    for name in FEATURE_NAMES:
        values = [s[name] for s in samples]
        centre = _median(values)
        mad = _median([abs(v - centre) for v in values])
        floor = 1.0 / window if name in PROPORTION_FEATURES else MIN_SCALE
        baseline[name] = {
            "centre": centre,
            "scale": max(mad * MAD_TO_SIGMA, floor),
        }
    return baseline


def collect_samples(paths, window, stride, seed=0):
    """One feature vector per window per client, across all calibration logs."""
    rng = random.Random(seed)
    samples, keys = [], set()
    for path in paths:
        for key, rows in group_by_key(load_log(path)).items():
            keys.add(key)
            for w in windows(rows, window, stride):
                if len(w) >= 10:  # too few requests to estimate ratios from
                    samples.append(compute_features(w, rng))
    return samples, keys


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True,
                   help="benign-only request logs")
    p.add_argument("--out", default="thresholds.json")
    p.add_argument("--window", type=int, default=30)
    p.add_argument("--stride", type=int, default=15)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    samples, keys = collect_samples(args.log, args.window, args.stride, args.seed)
    if len(samples) < 5:
        print("Only %d benign windows found; need at least 5 to calibrate. "
              "Generate more benign traffic first." % len(samples))
        return 2

    baseline = fit(samples, args.window)
    payload = {
        "window": args.window,
        "stride": args.stride,
        "n_windows": len(samples),
        "n_clients": len(keys),
        "clients": sorted(keys),
        # Recorded so campaign.py can reuse the same benign-only traffic for
        # its pair baseline without being told twice.
        "source_logs": [os.path.abspath(x) for x in args.log],
        "features": baseline,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print("calibrated on %d benign windows from %d clients -> %s\n"
          % (len(samples), len(keys), args.out))
    print("%-22s %10s %10s" % ("feature", "centre", "scale"))
    print("-" * 44)
    for name in FEATURE_NAMES:
        b = baseline[name]
        print("%-22s %10.4f %10.4f" % (name, b["centre"], b["scale"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
