"""Red team: an attacker that reads the detector's feedback and adapts.

Every earlier attacker was static. A real one gets caught, learns why, and
tries again. This one is a boundary prober (the kind the detector reliably
catches) that plays rounds:

    round: send 60 real queries under a fresh API key, get scored by the real
           detector against the real-customer baseline, and if flagged, change
           tactics and go again.

Five attackers are compared:

    informed    learns WHICH signals fired and reacts to each one.
    blind       learns only that it was flagged and changes one tactic at random.
    prior       no feedback, but already uses the countermeasures that beat the
                original ten-signal detector.
    prior_new   no feedback, but also knows the countermeasures to the eleventh
                signal (edit_neighbour_rate): far edits and no unedited seeds.
    split       prior_new's knowledge plus the natural counter to any per-key
                detector: each seed goes out on one key and its edited copy on
                another, so no single key ever holds a query and its neighbour.

Tactics (all attacker-side, all cheap):
    near_dup_rate, exact_dup_rate   more seeds, more edits per probe, no repeats
    herdan_c, token_entropy_norm    draw substitution words from a much bigger vocabulary
    len_cv                          use seeds of many different lengths
    template_share                  more seeds
    iat_burstiness                  switch to human-looking bursty timing
    label_balance, confidence       reseed from every source
    edit_neighbour_rate             more edits per probe, and stop sending the
                                    unedited seed

Success is three consecutive unflagged rounds with the same tactics. Evasion is
only worth something if the attacker is still probing, so each round records:

    probe density   share of the round's queries that still have a close but
                    different query among the others (the same test the detector
                    uses, applied by the experimenter over both keys)
    label flips     edited queries whose answer differs from their own seed's,
                    with seed labels read through a separate uncounted key

For the split attacker the existing cross-key linkage (detector/campaign.py) is
also tried, so the result says whether that layer catches what per-key scoring
cannot.

Timing is attacker-controlled, so each round's timestamps are assigned from the
attacker's chosen pacing instead of actually waiting. Labels and confidences
come from the live API.

    python eval/adaptive_attacker.py
    python eval/adaptive_attacker.py --trials 5 --max-rounds 12

Needs the API running with the DistilBERT victim, the real corpora built, and
data/logs/real_thresholds.json from eval/run_real_experiment.py. Standard
library plus matplotlib for the chart.

Writes eval/results/adaptive_attacker.json, .md and
eval/figures/adaptive_attacker.png.
"""

import argparse
import json
import math
import os
import random
import statistics
import sys
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from difflib import SequenceMatcher

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))
sys.path.insert(0, os.path.join(ROOT, "traffic"))

import campaign  # noqa: E402
from features import _edit_neighbour_rate, group_by_key, load_log  # noqa: E402
from real_corpus import available_sources, corpus_path, perturb_query  # noqa: E402
from score import MIN_FLAGS, score_client  # noqa: E402

THRESHOLDS = os.path.join(ROOT, "data", "logs", "real_thresholds.json")
RESULTS = os.path.join(HERE, "results")
FIGURE = os.path.join(HERE, "figures", "adaptive_attacker.png")

QUERIES_PER_ROUND = 60
CONFIRM_ROUNDS = 3
PACINGS = ("constant", "poisson", "bursty")
ORACLE_KEY = "flip-oracle"

LABELS = {
    "informed": "sees which signals fired",
    "blind": "sees only flagged or not, changes one tactic at random",
    "prior": "no feedback, uses the countermeasures to the original ten signals",
    "prior_new": "no feedback, also knows the countermeasures to the eleventh",
    "far": "no feedback, edits most of every seed so no probe stays close to it",
    "split": "no feedback, knows everything, and splits each probe pair across two keys",
    "split_far": "splits across two keys AND edits most of every seed",
}
MODES = tuple(LABELS)
NO_FEEDBACK = ("prior", "prior_new", "far", "split", "split_far")
COLOURS = {"informed": "#b3261e", "blind": "#2f5bd0", "prior": "#1f6d3f",
           "prior_new": "#7b2d8e", "far": "#0e7c86", "split": "#c77c02",
           "split_far": "#7a4a1d"}

# Limits on how far the attacker will stretch any one tactic.
MAX_SEEDS, MAX_EDITS, MAX_VOCAB = 40, 8, 5000


def similar(a, b):
    return SequenceMatcher(None, a.lower().split(), b.lower().split(), autojunk=False).ratio()


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
        self.query_seeds = True   # send the unedited seed too?
        self.split = False        # spread each seed and its copy over two keys?
        self.edit_fraction = 0.0  # edit at least this share of a seed's words
        self.by_len = sorted(pool, key=lambda t: len(t.split()))
        self.words = sorted({w for t in pool for w in t.split()})

    def describe(self):
        return ("seeds=%d edits=%d vocab=%d dedupe=%s lengths=%s pacing=%s seedq=%s keys=%d"
                % (self.n_seeds, self.edits, self.vocab_size, "y" if self.dedupe else "n",
                   "varied" if self.length_jitter else "narrow", self.pacing,
                   "y" if self.query_seeds else "n", 2 if self.split else 1))

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
        """One round: ([(seed_index, text, is_edit)], the seed texts)."""
        seeds = self.choose_seeds()
        vocab = self.vocab()
        plan = [(i, s, False) for i, s in enumerate(seeds)] if self.query_seeds else []
        sent = {text for _, text, _ in plan}
        budget = QUERIES_PER_ROUND - len(plan)
        i = 0
        while budget > 0 and seeds:
            seed_i = i % len(seeds)
            text = seeds[seed_i]
            n_edits = max(self.edits, math.ceil(self.edit_fraction * len(text.split())))
            for _ in range(n_edits):
                text = perturb_query(text, self.rng, vocab)
            tries = 0
            while self.dedupe and text in sent and tries < 6:
                text = perturb_query(text, self.rng, vocab)
                tries += 1
            sent.add(text)
            plan.append((seed_i, text, True))
            budget -= 1
            i += 1
        return plan[:QUERIES_PER_ROUND], seeds

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

    # --- fixed knowledge, for the attackers that get no feedback ---
    def apply_prior(self):
        """The countermeasures that beat the original ten-signal detector."""
        self.n_seeds, self.edits, self.vocab_size = 24, 3, 320
        self.dedupe, self.pacing = True, "poisson"

    def apply_prior_new(self):
        """Also the countermeasures to edit_neighbour_rate."""
        self.apply_prior()
        self.edits, self.query_seeds, self.length_jitter = 6, False, True

    def apply_split_far(self):
        """Both: a pair split over two keys, and a copy that is not close to its seed."""
        self.apply_split()
        self.edit_fraction = 0.7

    def apply_far(self):
        """Change most of every seed, so no probe stays within reach of it."""
        self.apply_prior_new()
        self.edit_fraction = 0.7

    def apply_split(self):
        """Everything above, plus one seed per key and its edited copy on the other."""
        self.n_seeds, self.edits, self.vocab_size = 30, 3, 320
        self.dedupe, self.pacing, self.length_jitter = True, "poisson", True
        self.query_seeds, self.split = True, True

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
        elif lever == "hide_seeds":
            self.query_seeds = False
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
        "edit_neighbour_rate": ("edits", "hide_seeds"),
    }

    def adapt_informed(self, flagged):
        used = []
        for feature in flagged:
            for lever in self.LEVERS.get(feature, ()):
                used.append(self.apply(lever))
        return sorted(set(used))

    def adapt_blind(self):
        return [self.apply(self.rng.choice(("seeds", "edits", "vocab", "dedupe", "lengths",
                                            "pacing", "mixed", "hide_seeds")))]


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


class Oracle:
    """Reads a seed's own label through a separate key that is never scored.

    The attacker does not need this. It exists so label flips can be counted
    even when the attacker never sends the unedited seed.
    """

    def __init__(self, base):
        self.base, self.cache = base, {}

    def label(self, text):
        if text not in self.cache:
            self.cache[text] = query_api(self.base, ORACLE_KEY, text)[0]
        return self.cache[text]


def make_rows(key, entries, timestamps):
    return [{"ts": t, "api_key": key, "input": text, "predicted_label": label,
             "confidence": conf}
            for t, (text, label, conf) in zip(timestamps, entries, strict=True)]


def play_round(att, base, key, cal, det_rng, workers, oracle, pair_cal):
    plan, seeds = att.schedule()
    if att.split:
        seen, roles = Counter(), []
        for seed_i, _, _ in plan:
            roles.append("a" if seen[seed_i] % 2 == 0 else "b")
            seen[seed_i] += 1
    else:
        roles = ["a"] * len(plan)
    keys = {"a": key + "-a", "b": key + "-b"} if att.split else {"a": key}

    def ask(i):
        return query_api(base, keys[roles[i]], plan[i][1])

    with ThreadPoolExecutor(max_workers=workers) as pool:
        answers = list(pool.map(ask, range(len(plan))))

    streams = {role: [] for role in keys}
    for role, (_, text, _), (label, conf) in zip(roles, plan, answers, strict=True):
        streams[role].append((text, label, conf))
    rows_by_key = {keys[role]: make_rows(keys[role], entries, att.timestamps(len(entries)))
                   for role, entries in streams.items()}

    worst = None
    for rows in rows_by_key.values():
        r = score_client(rows, cal["features"], cal["window"], cal["stride"], det_rng)
        if r and (worst is None
                  or (r["attack"], r["n_flags"], r["mean_z"])
                  > (worst["attack"], worst["n_flags"], worst["mean_z"])):
            worst = r
    flagged = sorted(worst["flags"], key=lambda f: -worst["z"][f]) if worst else []
    caught = bool(worst and worst["attack"])

    edited = [(seed_i, text, label) for (seed_i, text, is_edit), (label, _)
              in zip(plan, answers, strict=True) if is_edit]
    flips = sum(1 for seed_i, _, label in edited if label != oracle.label(seeds[seed_i]))
    sims = [similar(seeds[seed_i], text) for seed_i, text, _ in edited]

    rec = {
        "tactics": att.describe(),
        "signals_fired": worst["n_flags"] if worst else 0,
        "flagged": flagged,
        "caught": caught,
        "edited_queries": len(edited),
        "label_flips": flips,
        "probe_density": _edit_neighbour_rate([text for _, text, _ in plan]),
        "probe_similarity": statistics.mean(sims) if sims else 0.0,
        "unique_queries": len({text for _, text, _ in plan}),
        "campaign_confirmed": False,
    }
    if att.split and pair_cal is not None:
        links = campaign.link_pairs(rows_by_key, pair_cal["features"], det_rng)
        pooled_rows = sorted((r for rows in rows_by_key.values() for r in rows),
                             key=lambda r: r["ts"])
        pooled = score_client(pooled_rows, cal["features"], cal["window"], cal["stride"], det_rng)
        rec["linked"] = bool(links)
        rec["pooled_flags"] = pooled["n_flags"] if pooled else 0
        rec["campaign_confirmed"] = bool(links) and pooled is not None \
            and pooled["verdict"] == "ATTACK"
    rec["caught_any"] = caught or rec["campaign_confirmed"]
    return rec


def run_trial(mode, trial, pool, base, cal, max_rounds, workers, oracle, pair_cal):
    rng = random.Random(7000 + trial)  # trial already includes any --trial-offset
    att = Attacker(pool, rng)
    det_rng = random.Random(0)
    {"prior": att.apply_prior, "prior_new": att.apply_prior_new, "far": att.apply_far,
     "split": att.apply_split, "split_far": att.apply_split_far}.get(mode, lambda: None)()
    history, streak = [], 0
    for rnd in range(1, max_rounds + 1):
        rec = play_round(att, base, "adaptive-%s-%d-%d" % (mode, trial, rnd), cal, det_rng,
                         workers, oracle, pair_cal)
        rec["round"] = rnd
        if rec["caught"]:
            streak = 0
            if mode == "informed":
                rec["adapted"] = att.adapt_informed(rec["flagged"])
            elif mode == "blind":
                rec["adapted"] = att.adapt_blind()
            else:
                rec["adapted"] = []  # no feedback, so nothing to react to
        else:
            streak += 1
            rec["adapted"] = []
        history.append(rec)
        print("  %-9s trial %d round %2d  fired %d  %-7s density %.2f flips %2d  %s%s%s" % (
            mode, trial, rnd, rec["signals_fired"], "CAUGHT" if rec["caught"] else "passed",
            rec["probe_density"], rec["label_flips"], rec["tactics"],
            "  [linkage: %s]" % ("CAUGHT" if rec["campaign_confirmed"] else "missed")
            if "linked" in rec else "",
            ("   -> " + ",".join(rec["adapted"])) if rec["adapted"] else ""))
        if streak >= CONFIRM_ROUNDS:
            break
    evaded = streak >= CONFIRM_ROUNDS
    tail = history[-CONFIRM_ROUNDS:]
    evaded_with_linkage = evaded and len(tail) == CONFIRM_ROUNDS and not any(h["caught_any"] for h in tail)
    first_pass = next((h["round"] for h in history if not h["caught"]), None)
    return {"mode": mode, "trial": trial, "evaded": evaded,
            "evaded_with_linkage": evaded_with_linkage, "first_unflagged_round": first_pass,
            "rounds_played": len(history), "queries_spent": len(history) * QUERIES_PER_ROUND,
            "history": history}


def mean(values):
    values = list(values)
    return statistics.mean(values) if values else None


def summarise(trials):
    summary = {}
    for mode in MODES:
        mine = [t for t in trials if t["mode"] == mode]
        if not mine:
            continue
        done = [t for t in mine if t["evaded"]]
        rounds = [t["first_unflagged_round"] for t in mine if t["first_unflagged_round"]]
        summary[mode] = {
            "trials": len(mine), "evaded": len(done),
            "evaded_with_linkage": sum(t["evaded_with_linkage"] for t in mine),
            "median_first_unflagged_round": statistics.median(rounds) if rounds else None,
            "rounds_range": [min(rounds), max(rounds)] if rounds else None,
            "median_queries_spent": statistics.median(t["queries_spent"] for t in mine),
            "density_start": mean(t["history"][0]["probe_density"] for t in mine),
            "density_evaded": mean(t["history"][-1]["probe_density"] for t in done),
            "flips_start": mean(t["history"][0]["label_flips"] for t in mine),
            "flips_evaded": mean(t["history"][-1]["label_flips"] for t in done),
        }
    return summary


def fmt(x, digits=2):
    return "n/a" if x is None else ("%%.%df" % digits) % x


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--thresholds", default=THRESHOLDS)
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--trial-offset", type=int, default=0,
                   help="first trial number; each trial number is a different attacker seed")
    p.add_argument("--max-rounds", type=int, default=12)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        raise SystemExit("No baseline at %s. Run eval/run_real_experiment.py first." % args.thresholds)
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    if "edit_neighbour_rate" not in cal["features"]:
        raise SystemExit("This baseline predates edit_neighbour_rate. Refit it with:\n"
                         "  python eval/run_real_experiment.py --rescore")
    try:
        with urllib.request.urlopen(args.base_url + "/health", timeout=5) as r:
            if not json.loads(r.read()).get("model_loaded"):
                raise SystemExit("API is up but the model is not loaded yet.")
    except OSError as e:
        raise SystemExit("Cannot reach the API at %s: %s" % (args.base_url, e)) from e

    pair_cal = None
    if "split" in args.modes or "split_far" in args.modes:
        benign = []
        for path in cal.get("source_logs", []):
            if os.path.exists(path):
                benign.extend(load_log(path))
        pair_cal = campaign.fit_pair_baseline(group_by_key(benign), random.Random(0))
        if pair_cal is None:
            raise SystemExit("Could not fit a cross-key baseline from the calibration log.")

    pool = load_attack_pool()
    oracle = Oracle(args.base_url)
    print("attack pool: %d texts. baseline: %d windows from %d real customers.\n"
          % (len(pool), cal["n_windows"], cal["n_clients"]))

    trials = []
    for mode in args.modes:
        # Attackers with no feedback never change tactics, so more rounds add nothing.
        rounds = CONFIRM_ROUNDS if mode in NO_FEEDBACK else args.max_rounds
        for t in range(args.trial_offset, args.trial_offset + args.trials):
            trials.append(run_trial(mode, t, pool, args.base_url, cal, rounds, args.workers,
                                    oracle, pair_cal))

    summary = summarise(trials)
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "adaptive_attacker.json"), "w", encoding="utf-8") as fh:
        json.dump({"queries_per_round": QUERIES_PER_ROUND, "confirm_rounds": CONFIRM_ROUNDS,
                   "max_rounds": args.max_rounds, "min_flags": MIN_FLAGS,
                   "signals": len(cal["features"]), "summary": summary, "trials": trials}, fh,
                  indent=2)

    md = ["Boundary-probing attacker against the eleven-signal detector with the solo rule, %d queries per round, "
          "fresh API key each round. Success is %d consecutive unflagged rounds with unchanged "
          "tactics. Probe density is the share of queries that still have a close but different "
          "query among the others." % (QUERIES_PER_ROUND, CONFIRM_ROUNDS), "",
          "| Attacker | Trials | Fully evaded | First unflagged round (median, range) | "
          "Probe density: start, when evaded | Label flips per round: start, when evaded |",
          "|---|---|---|---|---|---|"]
    for mode in args.modes:
        s = summary[mode]
        rr = s["rounds_range"]
        md.append("| %s | %d | %d of %d | %s | %s, %s | %s, %s |" % (
            LABELS[mode], s["trials"], s["evaded"], s["trials"],
            "%s (%d to %d)" % (s["median_first_unflagged_round"], rr[0], rr[1]) if rr else "never",
            fmt(s["density_start"]), fmt(s["density_evaded"]),
            fmt(s["flips_start"], 1), fmt(s["flips_evaded"], 1)))
    for mode in ("split", "split_far"):
        if mode in summary:
            s = summary[mode]
            md += ["", "%s attacker: evaded the per-key detector in %d of %d trials, and evaded "
                   "per-key scoring plus cross-key linkage in %d of %d."
                   % (mode.replace("_", " ").capitalize(), s["evaded"], s["trials"],
                      s["evaded_with_linkage"], s["trials"])]
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "adaptive_attacker.md"), "w", encoding="utf-8") as fh:
        fh.write(text)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, axes = plt.subplots(1, 2, figsize=(11, 4))
        for mode in args.modes:
            mine = [t for t in trials if t["mode"] == mode]
            longest = max(len(t["history"]) for t in mine)
            for ax, key in ((axes[0], "signals_fired"), (axes[1], "probe_density")):
                ys = [statistics.mean(t["history"][r][key] for t in mine if len(t["history"]) > r)
                      for r in range(longest)]
                ax.plot(range(1, longest + 1), ys, marker="o", color=COLOURS[mode],
                        label=mode.replace("_", " "))
        axes[0].axhline(MIN_FLAGS - 0.5, color="#444", ls="--", lw=1)
        axes[0].set_title("Signals fired per round (flagged at %d+)" % MIN_FLAGS, fontsize=10)
        axes[1].set_title("Probe density: queries with a close edited neighbour", fontsize=10)
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
