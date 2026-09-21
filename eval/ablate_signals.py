"""Which signals is the detector actually relying on?

Rescores a labelled log with signals removed and reports how many attackers are
still caught and how many customers are wrongly flagged. Nothing is refitted:
the baseline, the 3.5 cutoff and the two-signal rule are exactly what score.py
uses, so a change in the result is caused only by the signals taken away.

    python eval/ablate_signals.py \\
        --log data/logs/real_eval.jsonl --thresholds data/logs/real_thresholds.json \\
        --attack-prefix atk-

Configurations tried:
    all signals               the detector as shipped
    drop each signal          leave-one-out, ten runs
    drop confidence signals   conf_p10 and low_conf_rate together, the two that
                              read the model's own confidence
    content only              the six signals that read only the query text
    timing and labels only    iat_burstiness and label_balance

The confidence signals are the interesting ones. They depend on how sure the
victim model is, so they may only work because this particular model is
overconfident. Removing them shows whether detection survives without them.

Writes eval/results/ablation_<tag>.md and .json.
"""

import argparse
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from features import FEATURE_NAMES, compute_features, group_by_key, load_log, windows  # noqa: E402
from score import MIN_FLAGS, Z_FLAG  # noqa: E402

CONFIDENCE = ("conf_p10", "low_conf_rate")
CONTENT = ("exact_dup_rate", "near_dup_rate", "herdan_c", "token_entropy_norm",
           "len_cv", "template_share")
TIMING_LABELS = ("iat_burstiness", "label_balance")


def window_z(rows, baseline, window, stride, rng):
    """Per-window z-scores for every signal, computed once and reused."""
    out = []
    for w in windows(rows, window, stride):
        feats = compute_features(w, rng)
        out.append({f: abs(feats[f] - baseline[f]["centre"]) / baseline[f]["scale"]
                    for f in FEATURE_NAMES})
    return out


def verdict(zs_per_window, keep):
    """score.py's rule restricted to `keep`: worst window wins, two flags to call it."""
    best = 0
    for zs in zs_per_window:
        best = max(best, sum(zs[f] >= Z_FLAG for f in keep))
    return best >= MIN_FLAGS


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", required=True)
    p.add_argument("--thresholds", required=True)
    p.add_argument("--attack-prefix", nargs="+", required=True)
    p.add_argument("--tag", default=None, help="output name suffix (default: log file name)")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    rng = random.Random(args.seed)
    per_client = {}
    for key, rows in group_by_key(load_log(args.log)).items():
        zs = window_z(rows, cal["features"], cal["window"], cal["stride"], rng)
        if zs:
            per_client[key] = zs
    is_attacker = {k: any(k.startswith(pre) for pre in args.attack_prefix) for k in per_client}
    n_atk = sum(is_attacker.values())
    n_ben = len(per_client) - n_atk
    if not n_atk or not n_ben:
        raise SystemExit("need both attackers and customers; found %d attackers, %d customers"
                         % (n_atk, n_ben))

    configs = [("all signals", FEATURE_NAMES)]
    for f in FEATURE_NAMES:
        configs.append(("drop %s" % f, tuple(x for x in FEATURE_NAMES if x != f)))
    configs += [
        ("drop confidence signals", tuple(x for x in FEATURE_NAMES if x not in CONFIDENCE)),
        ("content only", CONTENT),
        ("timing and labels only", TIMING_LABELS),
        ("confidence signals only", CONFIDENCE),
    ]

    rows_out = []
    for name, keep in configs:
        caught = sum(verdict(per_client[k], keep) for k in per_client if is_attacker[k])
        false = sum(verdict(per_client[k], keep) for k in per_client if not is_attacker[k])
        rows_out.append({"config": name, "signals": len(keep), "caught": caught,
                         "attackers": n_atk, "false_alarms": false, "customers": n_ben})

    tag = args.tag or os.path.splitext(os.path.basename(args.log))[0]
    md = ["Rescored %d attackers and %d customers with signals removed. Baseline, cutoff "
          "(z >= %.1f) and rule (%d signals) unchanged." % (n_atk, n_ben, Z_FLAG, MIN_FLAGS),
          "", "| Signals used | Count | Attackers caught | Customers wrongly flagged |",
          "|---|---|---|---|"]
    for r in rows_out:
        md.append("| %s | %d | %d of %d | %d of %d |" % (
            r["config"], r["signals"], r["caught"], r["attackers"],
            r["false_alarms"], r["customers"]))
    text = "\n".join(md) + "\n"

    out_dir = os.path.join(HERE, "results")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "ablation_%s.md" % tag), "w", encoding="utf-8") as fh:
        fh.write(text)
    with open(os.path.join(out_dir, "ablation_%s.json" % tag), "w", encoding="utf-8") as fh:
        json.dump({"log": os.path.basename(args.log), "attackers": n_atk,
                   "customers": n_ben, "runs": rows_out}, fh, indent=2)
    print(text)
    print("wrote eval/results/ablation_%s.md" % tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
