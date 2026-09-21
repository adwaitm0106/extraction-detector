"""How much traffic can this handle?

Two separate questions, measured separately because they have different limits.

A. The detector: how fast can it turn a request log into verdicts?
   A synthetic log is generated at several sizes and pushed through exactly what
   detector/score.py does: parse the JSON lines, group by API key, build 30-request
   windows, compute the ten signals, apply the flag rule. Each stage is timed.
   No API or model is involved, so the numbers are the detector alone.

B. The API: how many requests per second does the serving path sustain?
   A real uvicorn process is started with MODEL_STUB=1, which replaces DistilBERT
   with a word-list stand-in, so this measures the framework, request validation,
   locking and the audit log, NOT model inference. It is run twice, with the log
   fsynced on every line (the shipped default) and without, to show what that
   durability costs. The real model's ceiling is derived separately from the
   inference latency recorded in an earlier real run.

    python eval/bench_throughput.py
    python eval/bench_throughput.py --sizes 10000 100000 --api-seconds 8

Standard library only. Writes eval/results/throughput.json and throughput.md.
"""

import argparse
import http.client
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "detector"))

from calibrate import fit  # noqa: E402
from features import compute_features, group_by_key, load_log, windows  # noqa: E402
from score import LogTail, scan, score_client  # noqa: E402

WINDOW, STRIDE = 30, 15
REQUESTS_PER_CLIENT = 200
RESULTS = os.path.join(HERE, "results")


# --- A. detector ------------------------------------------------------------

def make_log(path, n_requests, seed=0):
    """A plausible request log: many clients, varied text, human-ish timing."""
    rng = random.Random(seed)
    vocab = ["w%d" % i for i in range(3000)]
    clients = max(1, n_requests // REQUESTS_PER_CLIENT)
    written = 0
    with open(path, "w", encoding="utf-8") as fh:
        for c in range(clients):
            t = 1.7e9 + rng.random() * 1000
            for _ in range(REQUESTS_PER_CLIENT):
                t += rng.expovariate(0.7)
                text = " ".join(rng.choice(vocab) for _ in range(rng.randint(4, 15)))
                fh.write(json.dumps({
                    "ts": t, "api_key": "client-%05d" % c, "input": text,
                    "predicted_label": rng.choice(("POSITIVE", "NEGATIVE")),
                    "confidence": rng.uniform(0.8, 0.999), "latency_ms": 60}) + "\n")
                written += 1
    return written, clients


def bench_detector(sizes):
    rng = random.Random(0)
    rows_out = []
    for size in sizes:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "requests.jsonl")
            n, clients = make_log(path, size)
            mb = os.path.getsize(path) / 1e6

            t0 = time.perf_counter()
            rows = load_log(path)
            t_parse = time.perf_counter() - t0

            t0 = time.perf_counter()
            by_key = group_by_key(rows)
            t_group = time.perf_counter() - t0

            # Baseline fitted on the first 20 clients, as calibrate.py would.
            samples = [compute_features(w, rng)
                       for k in sorted(by_key)[:20]
                       for w in windows(by_key[k], WINDOW, STRIDE)]
            baseline = fit(samples, WINDOW)

            t0 = time.perf_counter()
            n_windows = 0
            flagged = 0
            for client_rows in by_key.values():
                r = score_client(client_rows, baseline, WINDOW, STRIDE, rng)
                n_windows += len(windows(client_rows, WINDOW, STRIDE))
                flagged += bool(r and r["verdict"] == "ATTACK")
            t_score = time.perf_counter() - t0

        total = t_parse + t_group + t_score
        rows_out.append({
            "requests": n, "clients": clients, "log_mb": round(mb, 1),
            "windows": n_windows,
            "parse_s": round(t_parse, 2), "group_s": round(t_group, 2),
            "score_s": round(t_score, 2), "total_s": round(total, 2),
            "requests_per_s": round(n / total),
            "windows_per_s": round(n_windows / t_score),
        })
        r = rows_out[-1]
        print("  %8d requests  %5.1f MB  parse %5.2fs  group %5.2fs  score %6.2fs"
              "  total %6.2fs  -> %d req/s" % (
                  n, mb, t_parse, t_group, t_score, total, r["requests_per_s"]))
    return rows_out


def bench_watch(size=100000):
    """One --watch cycle: new traffic arrives, only that traffic is processed."""
    rng = random.Random(3)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "requests.jsonl")
        n, clients = make_log(path, size)
        rows = load_log(path)
        by_key = group_by_key(rows)
        samples = [compute_features(w, rng) for k in sorted(by_key)[:20]
                   for w in windows(by_key[k], WINDOW, STRIDE)]
        baseline = fit(samples, WINDOW)

        t0 = time.perf_counter()
        scan([path], baseline, WINDOW, STRIDE, rng)
        full = time.perf_counter() - t0

        tail, results = LogTail([path]), {}
        t0 = time.perf_counter()
        dirty, _ = tail.poll()
        for key in dirty:
            r = score_client(tail.by_key[key], baseline, WINDOW, STRIDE, rng)
            if r:
                results[key] = r
        first = time.perf_counter() - t0

        # Three busy clients each send 100 more requests.
        with open(path, "a", encoding="utf-8") as fh:
            for c in range(3):
                t = 2.0e9
                for _ in range(100):
                    t += rng.expovariate(0.7)
                    fh.write(json.dumps({
                        "ts": t, "api_key": "client-%05d" % c,
                        "input": "fresh query %d" % rng.randrange(10 ** 6),
                        "predicted_label": "POSITIVE", "confidence": 0.95,
                        "latency_ms": 60}) + "\n")
        t0 = time.perf_counter()
        dirty, _ = tail.poll()
        for key in dirty:
            score_client(tail.by_key[key], baseline, WINDOW, STRIDE, rng)
        cycle = time.perf_counter() - t0
    out = {"log_requests": n, "full_rescan_s": round(full, 2),
           "first_poll_s": round(first, 2), "incremental_cycle_ms": round(cycle * 1e3, 1),
           "speedup": round(full / cycle)}
    print("  --watch cycle on a %d-request log: full rescan %.2fs vs incremental %.1f ms (%dx)"
          % (n, full, cycle * 1e3, out["speedup"]))
    return out


def bench_one_window(repeats=2000):
    rng = random.Random(1)
    vocab = ["w%d" % i for i in range(3000)]
    window = [{"ts": float(i), "api_key": "k",
               "input": " ".join(rng.choice(vocab) for _ in range(rng.randint(4, 15))),
               "predicted_label": "POSITIVE", "confidence": 0.95} for i in range(WINDOW)]
    t0 = time.perf_counter()
    for _ in range(repeats):
        compute_features(window, rng)
    return (time.perf_counter() - t0) / repeats * 1e3


# --- B. API -----------------------------------------------------------------

def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_api(fsync, log_path, port):
    env = dict(os.environ, MODEL_STUB="1", LOG_PATH=log_path,
               LOG_FSYNC="1" if fsync else "0",
               BLOCKLIST_PATH=os.path.join(os.path.dirname(log_path), "none.json"))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit("API exited early")
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            c.request("GET", "/health")
            if b'"model_loaded":true' in c.getresponse().read():
                return proc
        except OSError:
            pass
        time.sleep(0.3)
    proc.kill()
    raise SystemExit("API did not become ready")


def load_test(port, seconds, workers):
    """Hammer /predict from several threads over persistent connections."""
    body = json.dumps({"input": "this was a genuinely great film"})
    headers = {"Content-Type": "application/json", "X-API-Key": "bench"}
    latencies, errors = [], [0]
    lock = threading.Lock()
    stop = time.time() + seconds

    def worker():
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        mine = []
        while time.time() < stop:
            t0 = time.perf_counter()
            try:
                conn.request("POST", "/predict", body=body, headers=headers)
                resp = conn.getresponse()
                resp.read()
                if resp.status != 200:
                    errors[0] += 1
            except OSError:
                errors[0] += 1
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                continue
            mine.append((time.perf_counter() - t0) * 1e3)
        with lock:
            latencies.extend(mine)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0
    latencies.sort()
    n = len(latencies)
    return {"requests": n, "errors": errors[0], "seconds": round(elapsed, 1),
            "requests_per_s": round(n / elapsed),
            "p50_ms": round(latencies[n // 2], 1), "p95_ms": round(latencies[int(n * 0.95)], 1)}


def bench_api(seconds, workers):
    out = {}
    for label, fsync in (("fsync_on", True), ("fsync_off", False)):
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            proc = start_api(fsync, os.path.join(tmp, "requests.jsonl"), port)
            try:
                load_test(port, 1.5, workers)  # warm up
                out[label] = load_test(port, seconds, workers)
            finally:
                proc.kill()
                proc.wait()
        r = out[label]
        print("  %-10s %5d req/s   p50 %6.1f ms   p95 %6.1f ms   (%d requests, %d errors)"
              % (label, r["requests_per_s"], r["p50_ms"], r["p95_ms"], r["requests"], r["errors"]))
    return out


def real_model_ceiling():
    """Requests/second the real model could serve, from latencies in an earlier real run."""
    path = os.path.join(ROOT, "data", "logs", "real_eval.jsonl")
    if not os.path.exists(path):
        return None
    lat = [r["latency_ms"] for r in load_log(path) if "latency_ms" in r]
    if not lat:
        return None
    med = statistics.median(lat)
    return {"median_inference_ms": med, "requests": len(lat),
            "ceiling_req_per_s": round(1000.0 / med, 1)}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sizes", type=int, nargs="+", default=[10000, 100000, 500000])
    p.add_argument("--api-seconds", type=float, default=10.0)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--skip-api", action="store_true")
    args = p.parse_args()

    machine = "%s, %s, %d logical CPUs, Python %s" % (
        platform.system(), platform.processor() or platform.machine(),
        os.cpu_count() or 0, platform.python_version())
    print("machine: %s\n" % machine)

    print("A. detector scoring (parse + group + features + rule)")
    det = bench_detector(args.sizes)
    win_ms = bench_one_window()
    print("  one 30-request window: %.2f ms to compute all ten signals" % win_ms)
    watch = bench_watch()
    print()

    api = None
    if not args.skip_api:
        print("B. API serving path with the stub model (%d threads, %.0fs each)"
              % (args.workers, args.api_seconds))
        api = bench_api(args.api_seconds, args.workers)
    ceiling = real_model_ceiling()

    results = {"machine": machine, "detector": det, "one_window_ms": round(win_ms, 2),
               "watch_cycle": watch, "api_stub": api, "real_model": ceiling}
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "throughput.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    md = ["Measured on: %s." % machine, "",
          "**Detector** (parse, group, signals, flag rule; no API or model involved)", "",
          "| Requests in log | Log size | Parse | Group | Score | Total | Throughput |",
          "|---|---|---|---|---|---|---|"]
    for r in det:
        md.append("| %s | %.1f MB | %.2fs | %.2fs | %.2fs | %.2fs | %s requests/s |" % (
            format(r["requests"], ","), r["log_mb"], r["parse_s"], r["group_s"],
            r["score_s"], r["total_s"], format(r["requests_per_s"], ",")))
    md += ["", "Computing the ten signals for one 30-request window takes %.2f ms." % win_ms]
    md += ["", "**Live `--watch` cycle** on a %s-request log: a full rescan takes %.2fs, reading only the new lines and rescoring the three clients that sent them takes %.1f ms."
           % (format(watch["log_requests"], ","), watch["full_rescan_s"], watch["incremental_cycle_ms"])]
    if api:
        md += ["", "**API serving path** (stub model, so this excludes inference)", "",
               "| Log durability | Requests/s | p50 latency | p95 latency |", "|---|---|---|---|"]
        for label, name in (("fsync_on", "fsync every line (default)"),
                            ("fsync_off", "no fsync")):
            r = api[label]
            md.append("| %s | %s | %.1f ms | %.1f ms |" % (
                name, format(r["requests_per_s"], ","), r["p50_ms"], r["p95_ms"]))
    if ceiling:
        md += ["", "**Real model ceiling.** Inference takes a median of %.0f ms per request "
               "and runs one request at a time under a lock, so DistilBERT on this CPU tops "
               "out near %.0f requests/s regardless of the API's own speed."
               % (ceiling["median_inference_ms"], ceiling["ceiling_req_per_s"])]
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "throughput.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    print("\nwrote eval/results/throughput.json and eval/results/throughput.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
