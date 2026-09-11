"""Draw the flags-per-client chart from a scored log.

    python eval/plot.py --log data/logs/requests.jsonl \\
        --thresholds thresholds.json --out eval/figures/flags_per_client.png

One horizontal bar per client, sorted by how many signals fired, with the
decision line at MIN_FLAGS. Attackers red, benign green, so the picture makes
the same point as the confusion matrix but at a glance. Needs matplotlib
(see eval/requirements.txt); nothing else in the project does.
"""

import argparse
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "detector"))

from features import group_by_key, load_log  # noqa: E402
from score import MIN_FLAGS, score_client  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True)
    p.add_argument("--thresholds", default="thresholds.json")
    p.add_argument("--out", default="eval/figures/flags_per_client.png")
    p.add_argument("--attack-prefix", nargs="+",
                   default=["L0-", "L1-", "L2-", "L3-", "L4-", "L5-", "atk-", "attacker"])
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed. Run:\n"
              "  .venv/Scripts/python.exe -m pip install -r eval/requirements.txt")
        return 2

    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    rows = []
    for path in args.log:
        rows.extend(load_log(path))
    rng = random.Random(args.seed)

    entries = []
    for key, client_rows in group_by_key(rows).items():
        r = score_client(client_rows, cal["features"], cal["window"], cal["stride"], rng)
        if r is None:
            continue
        truth = any(key.startswith(pre) for pre in args.attack_prefix)
        entries.append((key, r["n_flags"], truth))
    if not entries:
        print("Nothing scorable in the log.")
        return 2

    entries.sort(key=lambda e: (e[1], e[0]))
    names = [e[0] for e in entries]
    flags = [e[1] for e in entries]
    colors = ["#b3261e" if e[2] else "#1f6d3f" for e in entries]

    height = max(3.0, 0.32 * len(entries) + 1.2)
    fig, ax = plt.subplots(figsize=(8, height))
    ax.barh(names, flags, color=colors)
    ax.axvline(MIN_FLAGS - 0.5, color="#444", linestyle="--", linewidth=1)
    ax.text(MIN_FLAGS - 0.45, len(entries) - 0.6,
            "flagged at %d+ signals" % MIN_FLAGS, fontsize=8, color="#444")
    ax.set_xlabel("signals fired (out of 10)")
    ax.set_xlim(0, 10)
    ax.set_title("Detector output per client: red = actual attacker, green = benign",
                 fontsize=10)
    ax.tick_params(axis="y", labelsize=8)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    fig.savefig(args.out, dpi=150)
    print("wrote %s (%d clients)" % (args.out, len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
