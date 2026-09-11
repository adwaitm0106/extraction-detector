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
import time

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
    ]
    if not results:
        return None
    worst = max(results, key=lambda r: (r["n_flags"], r["mean_z"]))
    worst["n_windows"] = len(results)
    worst["n_requests"] = len(rows)
    worst["verdict"] = "ATTACK" if worst["n_flags"] >= MIN_FLAGS else "benign"
    return worst


# --- Alerting. Written to stdout so it shows up in a terminal during a demo
# --- and in the container logs in deployment.
def alert_line(key, r):
    signals = ", ".join("%s(%.1f)" % (n, r["z"][n])
                        for n in sorted(r["flags"], key=lambda n: -r["z"][n]))
    return ("[ALERT %s] EXTRACTION SUSPECTED  api_key=%s  flags=%d/%d  "
            "requests=%d  signals: %s"
            % (time.strftime("%H:%M:%S"), key, r["n_flags"], len(FEATURE_NAMES),
               r["n_requests"], signals))


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


def watch(args, baseline, window, stride, rng):
    """Tail the log, rescoring on an interval and alerting on new evidence.

    A key is announced once. It is announced again only when its evidence
    changes -- an operator watching a demo should see escalation, not the
    same line repeating every few seconds.
    """
    print("watching %s every %.1fs -- Ctrl+C to stop\n"
          % (", ".join(args.log), args.interval))
    announced = {}
    seen_requests = 0
    try:
        while True:
            results = scan(args.log, baseline, window, stride, rng)
            total = sum(r["n_requests"] for r in results.values())
            for key, r in sorted(results.items(),
                                 key=lambda kv: -kv[1]["n_flags"]):
                if r["verdict"] != "ATTACK":
                    continue
                fingerprint = tuple(sorted(r["flags"]))
                if announced.get(key) != fingerprint:
                    announced[key] = fingerprint
                    print(alert_line(key, r))
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
    else:
        print("No clients flagged; %d scored." % len(verdicts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
