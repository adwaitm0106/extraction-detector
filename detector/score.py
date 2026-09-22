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

One exception, added after the first red-team run (see README). The signal
edit_neighbour_rate detects the thing boundary probing cannot avoid doing,
and it was firing in every round an attacker got through, but alone, so the
two-signal rule discarded it. It may therefore flag a client by itself at
a stricter cutoff:

    Z_SOLO = 5.0    two coincident 3.5-sigma signals among 11 have a
                    false-alarm rate of about 1.2e-5 per window; one signal
                    matches that at |z| of about 4.9. Derived from the
                    existing rule, not from any result.

Only that signal is eligible. Noisy ones (confidence, timing, label balance)
have reached z of 4.3 to 17 on honest customers, so letting them flag alone
would flag customers. This one was exactly 0 on every real customer window
measured. The open risk is a customer who really does resubmit edited copies
of their own queries.

Usage:
    python detector/score.py --log data/logs/requests.jsonl \\
        --thresholds thresholds.json
"""

import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import (  # noqa: E402
    FEATURE_NAMES,
    compute_features,
    group_by_key,
    load_log,
    parse_row,
    windows_with_context,
)

Z_FLAG = 3.5
MIN_FLAGS = 2
Z_SOLO = 5.0
SOLO_SIGNALS = ("edit_neighbour_rate",)

# One plain sentence per signal, printed under each alert. An operator deciding
# whether to cut off a paying customer should not need to know what Herdan's C
# is to understand why the detector is worried.
EXPLAIN = {
    "exact_dup_rate": "repeats the exact same queries",
    "near_dup_rate": "sends many near-identical queries",
    "herdan_c": "uses an unusually narrow vocabulary",
    "token_entropy_norm": "word choice is unnaturally uniform or unnaturally skewed",
    "len_cv": "query lengths are unusually uniform",
    "template_share": "many queries share one structural template",
    "low_conf_rate": "unusually many queries where the model was unsure",
    "conf_p10": "the model's least-confident answers are far outside normal",
    "iat_burstiness": "request timing does not look human",
    "label_balance": "labels split unusually evenly, like systematic coverage",
    "edit_neighbour_rate": "keeps sending slightly edited copies of its own earlier queries, as boundary probing does",
}


def score_window(feats, baseline):
    """Per-feature robust z-scores, plus the flag count and mean deviation."""
    zs = {}
    for name in FEATURE_NAMES:
        b = baseline[name]
        zs[name] = abs(feats[name] - b["centre"]) / b["scale"]
    flagged = [n for n, z in zs.items() if z >= Z_FLAG]
    solo = [n for n in SOLO_SIGNALS if zs[n] >= Z_SOLO]
    return {
        "z": zs,
        "flags": flagged,
        "n_flags": len(flagged),
        "solo": solo,
        "attack": len(flagged) >= MIN_FLAGS or bool(solo),
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
        score_window(compute_features(w, rng, wide=wide), baseline)
        for w, wide in windows_with_context(rows, window, stride)
    ]
    if not results:
        return None
    worst = max(results, key=lambda r: (r["attack"], r["n_flags"], r["mean_z"]))
    worst["n_windows"] = len(results)
    worst["n_requests"] = len(rows)
    worst["verdict"] = "ATTACK" if worst["attack"] else "benign"
    return worst


# --- Alerting. Written to stdout so it shows up in a terminal during a demo
# --- and in the container logs in deployment.
def alert_line(key, r):
    top = sorted(r["flags"], key=lambda n: -r["z"][n])
    signals = ", ".join("%s(%.1f)" % (n, r["z"][n]) for n in top)
    why = "; ".join(EXPLAIN.get(n, n) for n in top)
    note = "  (one strong signal)" if r["n_flags"] < MIN_FLAGS else ""
    return ("[ALERT %s] EXTRACTION SUSPECTED  api_key=%s  flags=%d/%d%s  "
            "requests=%d  signals: %s\n  why: %s"
            % (time.strftime("%H:%M:%S"), key, r["n_flags"], len(FEATURE_NAMES),
               note, r["n_requests"], signals, why))


# --- Enforcement. Flagged keys are written to a small JSON file that the API
# --- re-reads on each request and answers with 429. A file rather than a
# --- socket keeps the detector and the API fully decoupled: either can restart
# --- without the other noticing.
def write_blocklist(path, verdicts):
    blocked = {
        key: {
            "since": time.time(),
            "flags": sorted(r["flags"], key=lambda n: -r["z"][n]),
            "why": [EXPLAIN.get(n, n)
                    for n in sorted(r["flags"], key=lambda n: -r["z"][n])],
        }
        for key, r in verdicts.items() if r["verdict"] == "ATTACK"
    }
    # Keep the original block time across rescans.
    previous = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                previous = json.load(fh).get("blocked", {})
        except (OSError, ValueError):
            previous = {}
    for key in blocked:
        if key in previous and "since" in previous[key]:
            blocked[key]["since"] = previous[key]["since"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"updated": time.time(), "blocked": blocked}, fh, indent=2)
    os.replace(tmp, path)  # atomic; the API never sees a half-written file
    return blocked


def scan(log_paths, baseline, window, stride, rng):
    """Score every client in the logs. Returns {key: result}."""
    rows = []
    for path in log_paths:
        if os.path.exists(path):
            rows.extend(load_log(path))
    out = {}
    for key, client_rows in sorted(group_by_key(rows).items()):
        r = score_client(client_rows, baseline, window, stride, rng)
        if r:
            out[key] = r
    return out


class LogTail:
    """Reads only the lines added to one or more JSONL logs since the last poll.

    Rescanning the whole log every interval costs more the longer the API has
    been running: measured, 100k logged requests takes 3 to 5 s to rescan, which
    is at or above the default 3 s interval, and 500k takes about 21 s. This
    keeps a byte offset per file and each client's rows in memory, so a poll
    costs in proportion to the NEW traffic, not to the size of the log.

    Reads are binary and stop at the last newline, so a line the API is still
    writing is left for the next poll instead of being parsed half-finished.
    If a file shrinks (rotated or truncated) everything is dropped and reread.
    Memory grows with the log, because every row is kept.
    """

    def __init__(self, paths):
        self.paths = list(paths)
        self.offsets = {p: 0 for p in self.paths}
        self.by_key = {}

    def poll(self):
        """Returns (keys that received new rows, whether all state was reset)."""
        reset = False
        for path in self.paths:
            try:
                if os.path.getsize(path) < self.offsets[path]:
                    reset = True
            except OSError:
                continue
        if reset:
            self.offsets = {p: 0 for p in self.paths}
            self.by_key = {}

        dirty = set()
        for path in self.paths:
            try:
                with open(path, "rb") as fh:
                    fh.seek(self.offsets[path])
                    data = fh.read()
            except OSError:
                continue
            end = data.rfind(b"\n")
            if end < 0:
                continue  # nothing complete yet
            self.offsets[path] += end + 1
            for line in data[:end + 1].decode("utf-8", errors="replace").splitlines():
                row = parse_row(line)
                if row is not None:
                    self.by_key.setdefault(row["api_key"], []).append(row)
                    dirty.add(row["api_key"])
        for key in dirty:
            self.by_key[key].sort(key=lambda r: float(r["ts"]))
        return dirty, reset


def watch(args, baseline, window, stride, rng):
    """Tail the log, rescoring on an interval and alerting on new evidence.

    A key is announced once. It is announced again only when its evidence
    changes -- an operator watching a demo should see escalation, not the
    same line repeating every few seconds.
    """
    print("watching %s every %.1fs -- Ctrl+C to stop"
          % (", ".join(args.log), args.interval))
    if args.enforce:
        print("enforcing: flagged keys are written to %s and the API answers "
              "them with 429\n" % args.enforce)
    else:
        print()
    announced = {}
    blocked_before = set()
    seen_requests = 0
    tail = LogTail(args.log)
    results = {}
    try:
        while True:
            dirty, reset = tail.poll()
            if reset:
                results.clear()
                announced.clear()
            for key in dirty:
                r = score_client(tail.by_key[key], baseline, window, stride, rng)
                if r:
                    results[key] = r
                else:
                    results.pop(key, None)
            total = sum(r["n_requests"] for r in results.values())
            for key, r in sorted(results.items(),
                                 key=lambda kv: -kv[1]["n_flags"]):
                if r["verdict"] != "ATTACK":
                    continue
                fingerprint = tuple(sorted(r["flags"]))
                if announced.get(key) != fingerprint:
                    announced[key] = fingerprint
                    print(alert_line(key, r))
            if args.enforce:
                now_blocked = set(write_blocklist(args.enforce, results))
                for key in sorted(now_blocked - blocked_before):
                    print("[BLOCK %s] api_key=%s now receives 429 on every request"
                          % (time.strftime("%H:%M:%S"), key))
                blocked_before = now_blocked
            if total != seen_requests:
                print("  ... %d requests from %d clients, %d flagged"
                      % (total, len(results),
                         sum(r["verdict"] == "ATTACK" for r in results.values())))
                seen_requests = total
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped. %d client(s) alerted during this session." % len(announced))
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log", nargs="+", required=True)
    p.add_argument("--thresholds", default="thresholds.json")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--watch", action="store_true",
                   help="tail the log and alert live as traffic arrives")
    p.add_argument("--interval", type=float, default=3.0,
                   help="seconds between rescans in --watch mode")
    p.add_argument("--enforce", nargs="?", const="blocked.json", default=None,
                   metavar="PATH",
                   help="write flagged keys to a blocklist the API enforces "
                        "with 429 (default path: blocked.json)")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    if not os.path.exists(args.thresholds):
        print("No baseline at %s -- run detector/calibrate.py on benign traffic "
              "first." % args.thresholds)
        return 2
    with open(args.thresholds, encoding="utf-8") as fh:
        cal = json.load(fh)
    baseline, window, stride = cal["features"], cal["window"], cal["stride"]

    rng = random.Random(args.seed)
    if args.watch:
        return watch(args, baseline, window, stride, rng)

    verdicts = scan(args.log, baseline, window, stride, rng)
    if not verdicts:
        print("No usable log lines found.")
        return 2

    # Enforce before any output path returns, so --json callers (the demo
    # script, a cron job) still get the blocklist written.
    if args.enforce:
        write_blocklist(args.enforce, verdicts)

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

    # --- Alerts after the table so they are the last thing on screen. ---
    flagged = [(k, r) for k, r in verdicts.items() if r["verdict"] == "ATTACK"]
    print()
    if flagged:
        for key, r in sorted(flagged, key=lambda kv: -kv[1]["n_flags"]):
            print(alert_line(key, r))
        print("\n%d of %d clients flagged." % (len(flagged), len(verdicts)))
        if args.enforce:
            print("blocklist written to %s" % args.enforce)
    else:
        print("No clients flagged; %d scored." % len(verdicts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
