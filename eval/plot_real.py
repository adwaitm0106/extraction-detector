"""Charts for the real-text results.

    python eval/plot_real.py

Draws two figures into eval/figures/:

  real_signal_separation.png
      Four signals, one panel each. Every dot is one 30-request window from one
      client, grouped by who sent it. The shaded band is "within 3.5 spreads of
      normal", the zone where a signal does not fire. Probers land outside it;
      harvesters sit inside it with the customers. That one picture is the
      whole real-data finding.

  real_flags_per_client.png
      How many of the ten signals fired for each client, with the line a client
      has to cross to be flagged.

The first chart needs the log and baseline from eval/run_real_experiment.py
(kept locally, not committed). The second only needs
eval/results/real_data.json, which is in the repo.
"""

import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from features import compute_features, group_by_key, load_log, windows_with_context  # noqa: E402
from score import MIN_FLAGS, Z_FLAG  # noqa: E402

LOGS = os.path.join(ROOT, "data", "logs")
EVAL_LOG = os.path.join(LOGS, "real_eval.jsonl")
THRESHOLDS = os.path.join(LOGS, "real_thresholds.json")
RESULTS = os.path.join(HERE, "results", "real_data.json")
FIGURES = os.path.join(HERE, "figures")

GROUPS = [
    ("customers, seen sources", "#1f6d3f"),
    ("customers, unseen source", "#2a9d8f"),
    ("probers", "#b3261e"),
    ("harvesters", "#c77c02"),
]
# Every panel here is a rate or a probability, so values live in [0, 1]. The
# "normal" band is clipped to that range: a band reaching 1.2 would suggest a
# confidence that cannot exist.
PANELS = [
    ("near_dup_rate", "near-duplicate rate"),
    ("herdan_c", "vocabulary richness"),
    ("exact_dup_rate", "exact repeat rate"),
    ("conf_p10", "10th percentile confidence"),
]


def group_of(key):
    if key.startswith("cust-imdb"):
        return "customers, unseen source"
    if key.startswith("cust-"):
        return "customers, seen sources"
    if "probe" in key or "boundary" in key:
        return "probers"
    return "harvesters"


def style(ax):
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)


def separation_chart(plt):
    if not (os.path.exists(EVAL_LOG) and os.path.exists(THRESHOLDS)):
        print("skipped real_signal_separation.png: run eval/run_real_experiment.py first")
        return
    with open(THRESHOLDS, encoding="utf-8") as fh:
        cal = json.load(fh)
    base = cal["features"]
    rng = random.Random(0)
    values = {g: {f: [] for f, _ in PANELS} for g, _ in GROUPS}
    for key, rows in group_by_key(load_log(EVAL_LOG)).items():
        for w, wide in windows_with_context(rows, cal["window"], cal["stride"]):
            feats = compute_features(w, rng, wide=wide)
            for f, _ in PANELS:
                values[group_of(key)][f].append(feats[f])

    fig, axes = plt.subplots(2, 2, figsize=(10, 7))
    jitter = random.Random(1)
    for ax, (feature, title) in zip(axes.flat, PANELS, strict=True):
        centre, scale = base[feature]["centre"], base[feature]["scale"]
        band_lo = max(0.0, centre - Z_FLAG * scale)
        band_hi = min(1.0, centre + Z_FLAG * scale)
        ax.axhspan(band_lo, band_hi, color="#9a9a94", alpha=0.18, lw=0)
        ax.axhline(centre, color="#6b6b66", lw=1, ls="--")
        for i, (group, colour) in enumerate(GROUPS):
            ys = values[group][feature]
            xs = [i + jitter.uniform(-0.18, 0.18) for _ in ys]
            ax.scatter(xs, ys, s=22, color=colour, alpha=0.8, edgecolors="none")
        ax.set_xticks(range(len(GROUPS)))
        ax.set_xticklabels([g.replace(", ", "\n") for g, _ in GROUPS], fontsize=8)
        ax.set_title(title, fontsize=10)
        every = [v for g, _ in GROUPS for v in values[g][feature]] + [band_lo, band_hi]
        lo, hi = min(every), max(every)
        pad = 0.06 * (hi - lo or 1)
        ax.set_ylim(max(-0.02, lo - pad), min(1.02, hi + pad))
        style(ax)

    fig.suptitle("Real text: probers land outside normal, harvesters sit inside it\n"
                 "(shaded band = within %.1f spreads of the baseline, where a signal "
                 "does not fire)" % Z_FLAG, fontsize=11)
    fig.tight_layout()
    out = os.path.join(FIGURES, "real_signal_separation.png")
    fig.savefig(out, dpi=150)
    print("wrote %s" % os.path.relpath(out, ROOT))


def flags_chart(plt):
    if not os.path.exists(RESULTS):
        print("skipped real_flags_per_client.png: run eval/run_real_experiment.py first")
        return
    with open(RESULTS, encoding="utf-8") as fh:
        clients = json.load(fh)["clients"]
    colour = dict(GROUPS)
    order = {g: i for i, (g, _) in enumerate(GROUPS)}
    clients.sort(key=lambda c: (-order[group_of(c["api_key"])], c["flags"], c["api_key"]))

    names = [c["api_key"] for c in clients]
    flags = [c["flags"] for c in clients]
    colours = [colour[group_of(c["api_key"])] for c in clients]

    fig, ax = plt.subplots(figsize=(8, 0.32 * len(clients) + 1.4))
    ax.barh(names, flags, color=colours)
    # A marker at the end of every bar, so a client with zero flags still shows
    # up in its group's colour instead of as an empty row.
    ax.scatter(flags, names, color=colours, s=30, zorder=3, edgecolors="white", linewidths=0.6)
    ax.axvline(MIN_FLAGS - 0.5, color="#444", ls="--", lw=1)
    ax.text(MIN_FLAGS - 0.4, len(clients) - 0.7, "flagged at %d+ signals" % MIN_FLAGS,
            fontsize=8, color="#444")
    ax.set_xlim(-0.3, 10)
    ax.set_xlabel("signals fired (out of 10)")
    ax.tick_params(axis="y", labelsize=8)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, c in GROUPS]
    ax.legend(handles, [g for g, _ in GROUPS], fontsize=8, loc="lower right")
    ax.set_title("Real text: signals fired per client", fontsize=10)
    style(ax)
    fig.tight_layout()
    out = os.path.join(FIGURES, "real_flags_per_client.png")
    fig.savefig(out, dpi=150)
    print("wrote %s" % os.path.relpath(out, ROOT))


def main():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        raise SystemExit("matplotlib is not installed. Run:\n"
                         "  .venv/Scripts/python.exe -m pip install -r eval/requirements.txt") from None
    os.makedirs(FIGURES, exist_ok=True)
    separation_chart(plt)
    flags_chart(plt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
