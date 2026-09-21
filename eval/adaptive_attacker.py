"""Red team: an attacker that reads the detector's feedback and adapts.

Every earlier attacker was static. A real one gets caught, learns why, and
tries again. This one is a boundary prober (the kind the detector reliably
catches) that plays rounds:

    round: send 60 real queries under a fresh API key, get scored by the real
           detector against the real-customer baseline, and if flagged, change
           tactics and go again.

Two feedback channels are compared:

    informed   the attacker learns WHICH signals fired and reacts to each one.
               This is what the API's 429 body used to leak, and what a
               dashboard exposed to customers would leak.
    blind      the attacker learns only that it was flagged and changes one
               tactic at random.

The gap between them is what leaking the reasons was worth.

A third attacker gets NO feedback at all but starts with the tactics the
informed attacker ends up using. The signals are documented, so an attacker
can know the standard countermeasures without ever being told what fired.
If it evades too, hiding the reasons is not what stands between an attacker
and the detector.

Tactics (all attacker-side, all cheap):
    near_dup_rate, exact_dup_rate   more seeds, more edits per probe, no repeats
    herdan_c, token_entropy_norm    draw substitution words from a much bigger vocabulary
    len_cv                          use seeds of many different lengths
    template_share                  more seeds
    iat_burstiness                  switch to human-looking bursty timing
    label_balance, confidence       reseed from every source

Success is three consecutive unflagged rounds with the same tactics. Because
evasion is only worth something if the attacker still learns about the
boundary, each round also records LABEL FLIPS: edited queries whose label
differs from their own seed's label. That is real boundary information, and it
is what evasion tends to cost.

Timing is attacker-controlled, so each round's timestamps are assigned from the
attacker's chosen pacing instead of actually waiting. Labels and confidences
come from the live API.

    python eval/adaptive_attacker.py
    python eval/adaptive_attacker.py --trials 5 --max-rounds 15

Needs the API running with the DistilBERT victim, the real corpora built, and
data/logs/real_thresholds.json from eval/run_real_experiment.py. Standard
library plus matplotlib for the chart.

Writes eval/results/adaptive_attacker.json, .md and
eval/figures/adaptive_attacker.png.
"""

import argparse
import json
import os
import random
import statistics
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))
sys.path.insert(0, os.path.join(ROOT, "traffic"))

from real_corpus import available_sources, corpus_path, perturb_query  # noqa: E402
from score import MIN_FLAGS, score_client  # noqa: E402

THRESHOLDS = os.path.join(ROOT, "data", "logs", "real_thresholds.json")
RESULTS = os.path.join(HERE, "results")
FIGURE = os.path.join(HERE, "figures", "adaptive_attacker.png")

QUERIES_PER_ROUND = 60
CONFIRM_ROUNDS = 3
PACINGS = ("constant", "poisson", "bursty")

LABELS = {
    "informed": "sees which signals fired",
    "blind": "sees only flagged or not, changes one tactic at random",
    "prior": "no feedback, starts with the informed attacker's final tactics",
}
MODES = tuple(LABELS)

# Limits on how far the attacker will stretch any one tactic.
MAX_SEEDS, MAX_EDITS, MAX_VOCAB = 40, 4, 5000


def load_attack_pool():
    """Every text the attacker may use, from the attack pools only."""
    texts = []
    for src in available_sources():
        with open(corpus_path(src), encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    r = json.loads(line)
                    if r["pool"] == "attack":
                        texts.append(r["text"])
    if not texts:
        raise SystemExit("No attack-pool texts. Run: python traffic/real_corpus.py")
    return texts


class Attacker:
    """The attacker's tactics. Starts lazy and gets more careful when caught."""

    def __init__(self, pool, rng):
        self.pool, self.rng = pool, rng
        self.n_seeds, self.edits, self.vocab_size = 3, 1, 20
        self.dedupe, self.length_jitter, self.pacing = False, False, "constant"
        self.mixed = False
        self.by_len = sorted(pool, key=lambda t: len(t.split()))
        self.words = sorted({w for t in pool for w in t.split()})

    def describe(self):
        return ("seeds=%d edits=%d vocab=%d dedupe=%s lengths=%s pacing=%s"
                % (self.n_seeds, self.edits, self.vocab_size, "y" if self.dedupe else "n",
                   "varied" if self.length_jitter else "narrow", self.pacing))

    def choose_seeds(self):
        if self.length_jitter:
            candidates = self.pool
        else:
            # Lazy attacker: grabs seeds of similar length.
            mid = len(self.by_len) // 2
            candidates = self.by_len[max(0, mid - 300): mid + 300]
        return self.rng.sample(candidates, min(self.n_seeds, len(candidates)))

    def vocab(self):
        return self.rng.sample(self.words, min(self.vocab_size, len(self.words)))

    def schedule(self):
        """The (seed_index, text, is_edit) sequence for one round."""
        seeds = self.choose_seeds()
        vocab = self.vocab()
        plan = [(i, s, False) for i, s in enumerate(seeds)]
        sent = set(seeds)
        budget = QUERIES_PER_ROUND - len(plan)
        i = 0
        while budget > 0 and seeds:
            seed_i = i % len(seeds)
            text = seeds[seed_i]
            for _ in range(self.edits):
                text = perturb_query(text, self.rng, vocab)
            tries = 0
            while self.dedupe and text in sent and tries < 6:
                text = perturb_query(text, self.rng, vocab)
                tries += 1
            sent.add(text)
            plan.append((seed_i, text, True))
            budget -= 1
            i += 1
        return plan[:QUERIES_PER_ROUND]

    def timestamps(self, n):
        t, out, burst = 1.0e9, [], self.rng.randint(3, 8)
        for i in range(n):
            if self.pacing == "constant":
                t += 1.0
            elif self.pacing == "poisson":
                t += self.rng.expovariate(1.0)
            else:  # bursty: short bursts separated by idle gaps, like a person
                if i and i % burst == 0:
                    t += self.rng.uniform(2.0, 6.0)
                    burst = self.rng.randint(3, 8)
                else:
                    t += self.rng.uniform(0.2, 0.5)
            out.append(t)
        return out

    def apply_prior(self):
        """Everything the informed attacker learned by round 3, known up front."""
        self.n_seeds, self.edits, self.vocab_size = 24, 3, 320
        self.dedupe, self.pacing = True, "poisson"

    # --- adaptation ---
    def apply(self, lever):
        """Push one tactic one step toward 'looks more like a customer'."""
        if lever == "seeds":
            self.n_seeds = min(MAX_SEEDS, self.n_seeds * 2)
        elif lever == "edits":
            self.edits = min(MAX_EDITS, self.edits + 1)
        elif lever == "vocab":
            self.vocab_size = min(MAX_VOCAB, self.vocab_size * 4)
        elif lever == "dedupe":
            self.dedupe = True
        elif lever == "lengths":
            self.length_jitter = True
        elif lever == "pacing":
            self.pacing = PACINGS[min(len(PACINGS) - 1, PACINGS.index(self.pacing) + 1)]
        elif lever == "mixed":
            self.mixed = True
            self.length_jitter = True
        return lever

    LEVERS = {
        "near_dup_rate": ("seeds", "edits", "dedupe"),
        "exact_dup_rate": ("dedupe", "seeds"),
        "herdan_c": ("vocab",),
        "token_entropy_norm": ("vocab",),
        "len_cv": ("lengths",),
        "template_share": ("seeds",),
        "iat_burstiness": ("pacing",),
        "label_balance": ("mixed",),
        "conf_p10": ("mixed",),
        "low_conf_rate": ("mixed",),
    }

    def adapt_informed(self, flagged):
        used = []
        for feature in flagged:
            for lever in self.LEVERS.get(feature, ()):
                used.append(self.apply(lever))
        return sorted(set(used))

    def adapt_blind(self):
        return [self.apply(self.rng.choice(("seeds", "edits", "vocab", "dedupe",
                                            "lengths", "pacing", "mixed")))]


def query_api(base, key, text):
    req = urllib.request.Request(
        base.rstrip("/") + "/predict",
        data=json.dumps({"input": text}).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-API-Key", key)
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
                return out["label"], float(out["confidence"])
        except (urllib.error.URLError, OSError, KeyError, ValueError):
            continue
    raise SystemExit("API stopped answering; is it running with RESPONSE_MODE=full?")


def play_round(att, base, key, cal, det_rng, workers):
    plan = att.schedule()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        answers = list(pool.map(lambda p: query_api(base, key, p[1]), plan))
    ts = att.timestamps(len(plan))
    rows = [{"ts": t, "api_key": key, "input": text, "predicted_label": label,
             "confidence": conf}
            for t, (_, text, _), (label, conf) in zip(ts, plan, answers, strict=True)]

    seed_label = {}
    for (seed_i, _, is_edit), (label, _) in zip(plan, answers, strict=True):
        if not is_edit:
            seed_label[seed_i] = label
    edited = [(seed_i, label) for (seed_i, _, is_edit), (label, _)
              in zip(plan, answers, strict=True) if is_edit]
    flips = sum(1 for seed_i, label in edited if label != seed_label.get(seed_i, label))

    r = score_client(rows, cal["features"], cal["window"], cal["stride"], det_rng)
    flagged = sorted(r["flags"], key=lambda f: -r["z"][f]) if r else []
    return {
        "tactics": att.describe(),
        "signals_fired": r["n_flags"] if r else 0,
        "flagged": flagged,
        "caught": bool(r and r["verdict"] == "ATTACK"),
        "edited_queries": len(edited),
        "label_flips": flips,
        "unique_queries": len({row["input"] for row in rows}),
    }


def run_trial(mode, trial, pool, base, cal, max_rounds, workers):
    rng = random.Random(7000 + trial)
    att = Attacker(pool, rng)
    det_rng = random.Random(0)
    if mode == "prior":
        att.apply_prior()
    history, streak = [], 0
    for rnd in range(1, max_rounds + 1):
        rec = play_round(att, base, "adaptive-%s-%d-%d" % (mode, trial, rnd), cal, det_rng, workers)
        rec["round"] = rnd
        if rec["caught"]:
            streak = 0
            if mode == "informed":
                rec["adapted"] = att.adapt_informed(rec["flagged"])
            elif mode == "blind":
                rec["adapted"] = att.adapt_blind()
            else:
                rec["adapted"] = []  # prior: no feedback, so nothing to react to
        else:
            streak += 1
            rec["adapted"] = []
        history.append(rec)
        print("  %-8s trial %d round %2d  fired %d  %-7s flips %2d  %s%s" % (
            mode, trial, rnd, rec["signals_fired"], "CAUGHT" if rec["caught"] else "passed",
            rec["label_flips"], rec["tactics"],
            ("   -> " + ",".join(rec["adapted"])) if rec["adapted"] else ""))
        if streak >= CONFIRM_ROUNDS:
            break
    evaded = streak >= CONFIRM_ROUNDS
    first_pass = next((h["round"] for h in history if not h["caught"]), None)
    return {"mode": mode, "trial": trial, "evaded": evaded, "first_unflagged_round": first_pass,
            "rounds_played": len(history), "queries_spent": len(history) * QUERIES_PER_ROUND,
            "history": history}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--thresholds", default=THRESHOLDS)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--max-rounds", type=int, default=12)
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        raise SystemExit("No baseline at %s. Run eval/run_real_experiment.py first." % args.thresholds)
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    try:
        with urllib.request.urlopen(args.base_url + "/health", timeout=5) as r:
            if not json.loads(r.read()).get("model_loaded"):
                raise SystemExit("API is up but the model is not loaded yet.")
    except OSError as e:
        raise SystemExit("Cannot reach the API at %s: %s" % (args.base_url, e)) from e

    pool = load_attack_pool()
    print("attack pool: %d texts. baseline: %d windows from %d real customers.\n"
          % (len(pool), cal["n_windows"], cal["n_clients"]))

    trials = []
    for mode in MODES:
        # The no-feedback attacker never changes tactics, so more rounds add nothing.
        rounds = CONFIRM_ROUNDS if mode == "prior" else args.max_rounds
        for t in range(args.trials):
            trials.append(run_trial(mode, t, pool, args.base_url, cal, rounds, args.workers))

    summary = {}
    for mode in MODES:
        mine = [t for t in trials if t["mode"] == mode]
        done = [t for t in mine if t["evaded"]]
        rounds = [t["first_unflagged_round"] for t in mine if t["first_unflagged_round"]]
        first = [t["history"][0]["label_flips"] for t in mine]
        last = [t["history"][-1]["label_flips"] for t in done]
        summary[mode] = {
            "trials": len(mine), "evaded": len(done),
            "median_first_unflagged_round": statistics.median(rounds) if rounds else None,
            "rounds_range": [min(rounds), max(rounds)] if rounds else None,
            "median_queries_spent": statistics.median(t["queries_spent"] for t in mine),
            "mean_flips_round1": statistics.mean(first),
            "mean_flips_when_evaded": statistics.mean(last) if last else None,
        }

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "adaptive_attacker.json"), "w", encoding="utf-8") as fh:
        json.dump({"queries_per_round": QUERIES_PER_ROUND, "confirm_rounds": CONFIRM_ROUNDS,
                   "max_rounds": args.max_rounds, "min_flags": MIN_FLAGS,
                   "summary": summary, "trials": trials}, fh, indent=2)

    md = ["Boundary-probing attacker, %d queries per round, fresh API key each round. "
          "Success is %d consecutive unflagged rounds with unchanged tactics." % (
              QUERIES_PER_ROUND, CONFIRM_ROUNDS), "",
          "| Attacker | Trials | Fully evaded | First unflagged round (median, range) | "
          "Label flips per round: start vs when evaded |",
          "|---|---|---|---|---|"]
    for mode, label in LABELS.items():
        s = summary[mode]
        rr = s["rounds_range"]
        md.append("| %s | %d | %d of %d | %s | %s |" % (
            label, s["trials"], s["evaded"], s["trials"],
            "%s (%d to %d)" % (s["median_first_unflagged_round"], rr[0], rr[1]) if rr else "never",
            "%.1f vs %s" % (s["mean_flips_round1"],
                            "%.1f" % s["mean_flips_when_evaded"] if s["mean_flips_when_evaded"] is not None else "n/a")))
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "adaptive_attacker.md"), "w", encoding="utf-8") as fh:
        fh.write(text)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
        colours = {"informed": "#b3261e", "blind": "#2f5bd0", "prior": "#1f6d3f"}
        for mode in MODES:
            mine = [t for t in trials if t["mode"] == mode]
            longest = max(len(t["history"]) for t in mine)
            for ax, key in ((axes[0], "signals_fired"), (axes[1], "label_flips")):
                ys = []
                for r in range(longest):
                    vals = [t["history"][r][key] for t in mine if len(t["history"]) > r]
                    ys.append(statistics.mean(vals))
                ax.plot(range(1, longest + 1), ys, marker="o", color=colours[mode],
                        label="%s attacker" % mode)
        axes[0].axhline(MIN_FLAGS - 0.5, color="#444", ls="--", lw=1)
        axes[0].set_title("Signals fired per round (flagged at %d+)" % MIN_FLAGS, fontsize=10)
        axes[1].set_title("Label flips per round (boundary information gained)", fontsize=10)
        for ax in axes:
            ax.set_xlabel("round")
            ax.legend(fontsize=8)
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
    print("wrote eval/results/adaptive_attacker.json and adaptive_attacker.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
