"""Evaluate the detector on real public text, end to end, and record the results.

Every real-data number in the README comes from this script. It needs the API
running and the corpora built (python traffic/real_corpus.py).

    python eval/run_real_experiment.py

What it does:

  1. Calibrate on 8 real customers: 2 each sending Reddit comments, tweets,
     Yelp reviews and Amazon reviews, all from the calibration pool.
  2. Test on 10 new customers: 2 per source again (seen sources, evaluation
     pool) plus 2 sending IMDB reviews, a source the baseline never saw.
  3. Test on attackers throttled to about one request a second with Poisson
     timing, using only the separate attack pool:
       - boundary probing on real tweets and on real Yelp reviews
       - harvesting a real corpus without repeats (Yelp, and all sources)
       - the same harvest split across 5 API keys
       - the old template boundary attacker, as a reference point
  4. Score every client, then write eval/results/real_data.json and
     eval/results/real_data.md.

To score again without generating traffic (after changing the detector), pass
--rescore: it refits the baseline from the saved calibration log and scores
the saved evaluation log. No API is needed. Pass the same --tag as the run
that produced the logs.

To evaluate a different victim model, start the API with MODEL_NAME set,
point --base-url at it, and pass --tag so the outputs do not overwrite the
first model's. --log must be the LOG_PATH that server writes to.

Customers and attackers run in separate waves so the API is never saturated:
the log records server-side timestamps, and heavy queueing would distort the
timing features for everyone.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from features import FEATURE_NAMES, group_by_key, load_log  # noqa: E402
from score import MIN_FLAGS, Z_FLAG, score_client  # noqa: E402

PY = sys.executable
GEN = os.path.join(ROOT, "traffic", "generate.py")
LOGS = os.path.join(ROOT, "data", "logs")
LOG = os.path.join(LOGS, "requests.jsonl")
CALIB_LOG = os.path.join(LOGS, "real_calib.jsonl")
EVAL_LOG = os.path.join(LOGS, "real_eval.jsonl")
THRESHOLDS = os.path.join(LOGS, "real_thresholds.json")
BLOCKLIST = os.path.join(ROOT, "blocked.json")
RESULTS = os.path.join(HERE, "results")
TAG = ""

SEEN = ("reddit", "twitter", "yelp", "amazon")
UNSEEN = ("imdb",)


def benign(key, source, pool, seed, n):
    return (key, ["--profile", "real-benign", "--source", source, "--pool", pool,
                  "--n", str(n), "--rate", "1.5", "--jitter", "0.5",
                  "--api-key", key, "--seed", str(seed)])


def attacker(key, profile, n, seed, source=None, split=1):
    a = ["--profile", profile, "--n", str(n), "--rate", "1.2",
         "--attacker-rate", "1.2", "--attacker-pacing", "poisson", "--seed", str(seed)]
    if source:
        a += ["--source", source]
    a += (["--split", str(split), "--attacker-key", key] if split > 1 else ["--api-key", key])
    return (key, a)


def run_wave(label, clients):
    t0 = time.time()
    procs = [(k, subprocess.Popen([PY, GEN] + a, cwd=ROOT, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, text=True))
             for k, a in clients]
    failed = []
    for k, p in procs:
        _, err = p.communicate()
        if p.returncode != 0:
            failed.append("%s exited %d: %s" % (k, p.returncode, (err or "").strip()[-300:]))
    print("  %-26s %2d processes, %.0fs" % (label, len(procs), time.time() - t0))
    if failed:
        raise SystemExit("traffic failed:\n  " + "\n  ".join(failed))


def rotate(dst):
    if os.path.exists(LOG):
        os.replace(LOG, dst)


def group_of(key):
    if key.startswith("cust-imdb"):
        return "benign (unseen source)"
    if key.startswith("cust-"):
        return "benign (seen source)"
    return "attacker"


def retag(tag, log):
    """Point every output path at a tagged copy, so a second model does not overwrite the first."""
    global LOG, CALIB_LOG, EVAL_LOG, THRESHOLDS, TAG
    TAG = ("_" + tag) if tag else ""
    LOG = log
    CALIB_LOG = os.path.join(LOGS, "real_calib%s.jsonl" % TAG)
    EVAL_LOG = os.path.join(LOGS, "real_eval%s.jsonl" % TAG)
    THRESHOLDS = os.path.join(LOGS, "real_thresholds%s.json" % TAG)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--n", type=int, default=60, help="requests per client")
    p.add_argument("--tag", default="", help="suffix for outputs, e.g. roberta")
    p.add_argument("--log", default=LOG, help="request log the API writes to")
    p.add_argument("--rescore", action="store_true",
                   help="refit and rescore the saved logs; no API, no new traffic")
    args = p.parse_args()
    retag(args.tag, args.log)

    os.makedirs(LOGS, exist_ok=True)
    os.makedirs(RESULTS, exist_ok=True)
    if args.rescore:
        for path in (CALIB_LOG, EVAL_LOG):
            if not os.path.exists(path):
                raise SystemExit("--rescore needs %s from an earlier run" % path)
        n = args.n
    else:
        try:
            with urllib.request.urlopen(args.base_url + "/health", timeout=5) as r:
                if not json.loads(r.read()).get("model_loaded"):
                    raise SystemExit("API is up but the model has not loaded yet.")
        except OSError as e:
            raise SystemExit("Cannot reach the API at %s: %s" % (args.base_url, e)) from e
        if os.path.exists(LOG):
            os.replace(LOG, os.path.join(LOGS, "requests.stale.jsonl"))
            print("moved an existing requests.jsonl aside to requests.stale.jsonl")
        if os.path.exists(BLOCKLIST):
            os.replace(BLOCKLIST, BLOCKLIST + ".stale")  # a stale block would 429 our attackers
        n = args.n

    # --- 1. calibration: benign only, calibration pool only ---
    print("\n[1/3] calibration")
    if not args.rescore:
        run_wave("8 real customers", [
            benign("cal-%s-%d" % (s, i), s, "calib", 1000 + 10 * j + i, n)
            for j, s in enumerate(SEEN) for i in range(2)])
        rotate(CALIB_LOG)
    out = subprocess.run([PY, os.path.join(ROOT, "detector", "calibrate.py"),
                          "--log", CALIB_LOG, "--out", THRESHOLDS],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("calibration failed:\n" + out.stdout + out.stderr)
    print("  " + out.stdout.splitlines()[0])

    # --- 2. evaluation: new customers, then attackers, in separate waves ---
    print("\n[2/3] evaluation traffic" + (" (saved log, not regenerated)" if args.rescore else ""))
    if not args.rescore:
        run_wave("10 new customers", [
            benign("cust-%s-%d" % (s, i), s, "eval", 2000 + 10 * j + i, n)
            for j, s in enumerate(SEEN + UNSEEN) for i in range(2)])
        run_wave("attackers (10 keys)", [
            attacker("atk-probe-twitter", "real-probe", n, 3001, "twitter"),
            attacker("atk-probe-yelp", "real-probe", n, 3002, "yelp"),
            attacker("atk-harvest-yelp", "real-harvest", n, 3003, "yelp"),
            attacker("atk-harvest-mixed", "real-harvest", n, 3004, "mixed"),
            attacker("atk-harvest-split", "real-harvest", 150, 3005, "amazon", split=5),
            attacker("atk-template-boundary", "boundary", n, 3006),
        ])
        rotate(EVAL_LOG)

    # --- 3. scoring ---
    print("\n[3/3] scoring")
    with open(THRESHOLDS, encoding="utf-8") as fh:
        cal = json.load(fh)
    rows = load_log(EVAL_LOG)
    import random
    rng = random.Random(0)
    clients = []
    for key, client_rows in sorted(group_by_key(rows).items()):
        r = score_client(client_rows, cal["features"], cal["window"], cal["stride"], rng)
        if r is None:
            continue
        top = sorted(r["flags"], key=lambda f: -r["z"][f])
        clients.append({
            "api_key": key, "group": group_of(key), "requests": r["n_requests"],
            "flags": r["n_flags"], "verdict": r["verdict"],
            "signals": [{"name": f, "z": round(r["z"][f], 1)} for f in top],
        })

    def rate(group, verdict):
        g = [c for c in clients if c["group"] == group]
        hit = sum(c["verdict"] == verdict for c in g)
        return hit, len(g)

    caught, n_atk = rate("attacker", "ATTACK")
    fp_seen, n_seen = rate("benign (seen source)", "ATTACK")
    fp_unseen, n_unseen = rate("benign (unseen source)", "ATTACK")

    # Which signals actually carry detection on real text.
    fire = {}
    for f in FEATURE_NAMES:
        atk = [c for c in clients if c["group"] == "attacker"]
        ben = [c for c in clients if c["group"] != "attacker"]
        fire[f] = {
            "attackers": sum(any(s["name"] == f for s in c["signals"]) for c in atk),
            "benign": sum(any(s["name"] == f for s in c["signals"]) for c in ben),
        }

    lat = [r.get("latency_ms", 0) for r in rows]
    results = {
        "baseline": {"windows": cal["n_windows"], "clients": cal["n_clients"],
                     "window": cal["window"], "z_flag": Z_FLAG, "min_flags": MIN_FLAGS},
        "requests_scored": len(rows),
        "median_latency_ms": statistics.median(lat) if lat else None,
        "detection": {"caught": caught, "attackers": n_atk},
        "false_positives": {"seen_source": [fp_seen, n_seen],
                            "unseen_source": [fp_unseen, n_unseen]},
        "signal_firing": fire,
        "clients": clients,
    }
    with open(os.path.join(RESULTS, "real_data%s.json" % TAG), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    md = []
    md.append("Baseline: %d windows from %d real customers. Flag at z >= %.1f on >= %d signals."
              % (cal["n_windows"], cal["n_clients"], Z_FLAG, MIN_FLAGS))
    md.append("")
    md.append("| Client | Group | Requests | Signals | Verdict | Strongest signals |")
    md.append("|---|---|---|---|---|---|")
    order = {"attacker": 0, "benign (seen source)": 1, "benign (unseen source)": 2}
    for c in sorted(clients, key=lambda c: (order[c["group"]], -c["flags"], c["api_key"])):
        sig = ", ".join("%s (%.1f)" % (s["name"], s["z"]) for s in c["signals"][:3]) or "none"
        md.append("| `%s` | %s | %d | %d | %s | %s |" % (
            c["api_key"], c["group"], c["requests"], c["flags"], c["verdict"], sig))
    md.append("")
    md.append("Attackers caught: **%d of %d**. False alarms: **%d of %d** customers on seen "
              "sources, **%d of %d** on the unseen source." % (
                  caught, n_atk, fp_seen, n_seen, fp_unseen, n_unseen))
    md.append("")
    md.append("| Signal | Fired on attackers | Fired on customers |")
    md.append("|---|---|---|")
    for f in FEATURE_NAMES:
        md.append("| `%s` | %d / %d | %d / %d |" % (
            f, fire[f]["attackers"], n_atk, fire[f]["benign"], n_seen + n_unseen))
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "real_data%s.md" % TAG), "w", encoding="utf-8") as fh:
        fh.write(text)

    print()
    print(text)
    print("median inference latency %s ms over %d requests"
          % (results["median_latency_ms"], len(rows)))
    print("wrote eval/results/real_data%s.json and eval/results/real_data%s.md" % (TAG, TAG))
    return 0


if __name__ == "__main__":
    sys.exit(main())
