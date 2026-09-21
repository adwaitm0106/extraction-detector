"""Put two victim models side by side.

Reads the outputs of eval/run_real_experiment.py and eval/ablate_signals.py for
two victims and reports, in one table:

    how confident each victim is on real customer text
    what the learned baseline looks like for the confidence signals
    how many attackers the detector catches and how many customers it flags
    what happens when the confidence signals are removed

    python eval/compare_victims.py --a distilbert --b roberta

Inputs, for a tag T ('distilbert' means the untagged first-run files):
    data/logs/real_eval[_T].jsonl     data/logs/real_thresholds[_T].json
    eval/results/real_data[_T].json   eval/results/ablation_real_T.json

Writes eval/results/victim_comparison.md and .json.
"""

import argparse
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from features import load_log  # noqa: E402

LOGS = os.path.join(ROOT, "data", "logs")
RESULTS = os.path.join(HERE, "results")


def suffix(tag):
    return "" if tag == "distilbert" else "_" + tag


def profile(tag):
    s = suffix(tag)
    rows = [r for r in load_log(os.path.join(LOGS, "real_eval%s.jsonl" % s))
            if r["api_key"].startswith("cust-")]
    conf = sorted(float(r["confidence"]) for r in rows)
    labels = sorted({r["predicted_label"] for r in rows})
    with open(os.path.join(LOGS, "real_thresholds%s.json" % s), encoding="utf-8") as fh:
        cal = json.load(fh)["features"]
    with open(os.path.join(RESULTS, "real_data%s.json" % s), encoding="utf-8") as fh:
        data = json.load(fh)
    with open(os.path.join(RESULTS, "ablation_real_%s.json" % tag), encoding="utf-8") as fh:
        abl = {r["config"]: r for r in json.load(fh)["runs"]}
    n = len(conf)
    return {
        "labels": labels,
        "customer_requests": n,
        "median_confidence": statistics.median(conf),
        "share_at_least_99": sum(c >= 0.99 for c in conf) / n,
        "share_below_90": sum(c < 0.90 for c in conf) / n,
        "baseline_conf_p10_centre": cal["conf_p10"]["centre"],
        "baseline_conf_p10_spread": cal["conf_p10"]["scale"],
        "baseline_low_conf_rate_centre": cal["low_conf_rate"]["centre"],
        "caught": data["detection"]["caught"],
        "attackers": data["detection"]["attackers"],
        "false_seen": data["false_positives"]["seen_source"],
        "false_unseen": data["false_positives"]["unseen_source"],
        "ablation": {k: abl[k] for k in ("all signals", "drop confidence signals",
                                         "content only", "confidence signals only")},
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--a", default="distilbert")
    p.add_argument("--b", default="roberta")
    args = p.parse_args()

    a, b = profile(args.a), profile(args.b)
    pct = lambda x: "%.1f%%" % (100 * x)  # noqa: E731

    rows = [
        ("Labels the model returns", ", ".join(a["labels"]), ", ".join(b["labels"])),
        ("Median confidence on real customer text", "%.3f" % a["median_confidence"],
         "%.3f" % b["median_confidence"]),
        ("Answers at 99% confidence or higher", pct(a["share_at_least_99"]),
         pct(b["share_at_least_99"])),
        ("Answers below 90% confidence", pct(a["share_below_90"]), pct(b["share_below_90"])),
        ("Baseline centre for 10th percentile confidence",
         "%.3f" % a["baseline_conf_p10_centre"], "%.3f" % b["baseline_conf_p10_centre"]),
        ("Baseline spread for 10th percentile confidence",
         "%.3f" % a["baseline_conf_p10_spread"], "%.3f" % b["baseline_conf_p10_spread"]),
    ]
    md = ["| | %s | %s |" % (args.a, args.b), "|---|---|---|"]
    md += ["| %s | %s | %s |" % r for r in rows]
    md += ["", "| Detector result | %s | %s |" % (args.a, args.b), "|---|---|---|",
           "| Attackers caught, all signals | %d of %d | %d of %d |" % (
               a["caught"], a["attackers"], b["caught"], b["attackers"]),
           "| Customers wrongly flagged, seen sources | %d of %d | %d of %d |" % (
               a["false_seen"][0], a["false_seen"][1], b["false_seen"][0], b["false_seen"][1]),
           "| Customers wrongly flagged, unseen source | %d of %d | %d of %d |" % (
               a["false_unseen"][0], a["false_unseen"][1], b["false_unseen"][0], b["false_unseen"][1])]
    for cfg in ("drop confidence signals", "content only", "confidence signals only"):
        ra, rb = a["ablation"][cfg], b["ablation"][cfg]
        md.append("| Attackers caught, %s | %d of %d | %d of %d |" % (
            cfg, ra["caught"], ra["attackers"], rb["caught"], rb["attackers"]))
    text = "\n".join(md) + "\n"

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "victim_comparison.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    with open(os.path.join(RESULTS, "victim_comparison.json"), "w", encoding="utf-8") as fh:
        json.dump({args.a: a, args.b: b}, fh, indent=2)
    print(text)
    print("wrote eval/results/victim_comparison.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
