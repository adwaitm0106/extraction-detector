"""Traffic generator for the extraction experiments.

Drives the victim API with labelled traffic so the detector has ground truth
to be evaluated against. Each client is given its own API key, which is what
ties a log line back to the profile that produced it.

Profiles
    benign      Short bursts of natural sentences at human pace, with the
                repetition real users produce.
    random      High-rate uniform word salad. Broad input-space coverage.
    boundary    Near-duplicate probes around a few seed sentences.
    sweep       Deterministic enumeration of a template grid.
    natural     Natural-looking sentences, enumerated systematically. Designed
                to pass per-key content checks: the attack is visible only in
                aggregate coverage, not in any single query.
    real-benign   Real sentences (Reddit, tweets, reviews) drawn at random
                  from a public corpus, at human pace. See real_corpus.py.
    real-harvest  An attacker walking a real corpus without repeats: the
                  surrogate-dataset collection a real extraction looks like.
    real-probe    An attacker making one-token edits to a few real sentences
                  to find where the label flips.
    mixed       Several benign clients plus one attacker, run concurrently --
                the realistic case, where the attacker must be picked out of
                normal traffic rather than observed in isolation.

Examples
    python traffic/generate.py --profile benign   --n 200
    python traffic/generate.py --profile boundary --n 400 --rate 25
    python traffic/generate.py --profile mixed    --duration 60

Standard library only, so it runs against a container with nothing installed.
"""

import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from corpus import (  # noqa: E402
    benign_query,
    boundary_probe_query,
    natural_query,
    random_ood_query,
    sweep_query,
)

from real_corpus import available_sources, load_pool, perturb_query  # noqa: E402

ATTACK_PROFILES = ("random", "boundary", "sweep", "natural",
                   "real-harvest", "real-probe")
BENIGN_PROFILES = ("benign", "real-benign")
REAL_PROFILES = ("real-benign", "real-harvest", "real-probe")


# --- One HTTP call. Failures are counted, never raised: a generator that dies
# --- partway through leaves a half-written log that is worse than useless.
def send(base, api_key, text, timeout=30):
    req = urllib.request.Request(
        base.rstrip("/") + "/predict",
        data=json.dumps({"input": text}).encode("utf-8"),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1


# --- A single client: one API key, one query generator, one pacing policy. ---
class Client:
    def __init__(self, base, api_key, profile, seed, rate, n=None,
                 duration=None, burst=False, jitter=0.0, pacing="constant",
                 index_offset=0, index_step=1, source=None, pool=None):
        self.base, self.api_key, self.profile = base, api_key, profile
        self.rng = random.Random(seed)
        self.rate, self.n, self.duration, self.burst = rate, n, duration, burst
        # Fractional timing jitter. A patient attacker randomises inter-arrival
        # times to look less like a machine, so the detector must not depend on
        # metronome-regular timing.
        self.jitter = jitter
        # "poisson" draws each gap from an exponential distribution, which is
        # what memoryless arrivals look like. This is the strongest evasion of
        # timing-based detection available to an attacker who is willing to be
        # slow, so the detector must be tested against it.
        self.pacing = pacing
        # Grid position for a split campaign: member r of K walks the template
        # grid at offset r, step K, so the members between them cover exactly
        # the same ground one client would have covered alone.
        self.index_offset, self.index_step = index_offset, index_step
        # Real-text profiles draw from a cached public corpus, loaded on first
        # use so template profiles never need the corpora to exist.
        self.source, self.pool = source, pool
        self._texts = self._seeds = self._vocab = None
        self.codes = Counter()
        self.sent = 0
        self._i = 0
        self._last = ""

    def next_query(self):
        if self.profile == "benign":
            # Real users repeat themselves; ~20% of queries are a re-ask.
            if self._i and self.rng.random() < 0.2:
                return self._last
            self._last = benign_query(self.rng)
            return self._last
        if self.profile == "random":
            return random_ood_query(self.rng)
        if self.profile == "boundary":
            return boundary_probe_query(self.rng)
        if self.profile == "sweep":
            return sweep_query(self.index_offset + self._i * self.index_step)
        if self.profile == "natural":
            return natural_query(self.index_offset + self._i * self.index_step)
        if self.profile in REAL_PROFILES:
            return self._real_query()
        raise ValueError("unknown profile " + self.profile)

    def _real_texts(self):
        if self._texts is None:
            pool = "attack" if self.profile in ATTACK_PROFILES else (self.pool or "eval")
            sources = (available_sources() if self.source in (None, "mixed")
                       else [self.source])
            if not sources:
                raise FileNotFoundError(
                    "No corpora built yet. Run: python traffic/real_corpus.py")
            texts = []
            for src in sources:
                texts.extend(load_pool(src, pool))
            # Harvest members of a split campaign must agree on one ordering so
            # their partitions tile the corpus; everyone else shuffles freely.
            order = random.Random(4242) if self.profile == "real-harvest" else self.rng
            order.shuffle(texts)
            self._texts = texts
        return self._texts

    def _real_query(self):
        texts = self._real_texts()
        if self.profile == "real-benign":
            # Same re-ask habit as the template customers.
            if self._i and self.rng.random() < 0.2:
                return self._last
            self._last = self.rng.choice(texts)
            return self._last
        if self.profile == "real-harvest":
            return texts[(self.index_offset + self._i * self.index_step) % len(texts)]
        if self.profile == "real-probe":
            if self._seeds is None:
                self._seeds = texts[:5]
                self._vocab = [w for t in texts[:400] for w in t.split()]
            return perturb_query(self.rng.choice(self._seeds), self.rng, self._vocab)
        raise ValueError("unknown profile " + self.profile)

    def run(self, stop_event):
        started = time.time()
        interval = 1.0 / self.rate if self.rate > 0 else 0.0
        next_at = started
        while not stop_event.is_set():
            if self.n is not None and self.sent >= self.n:
                break
            if self.duration is not None and time.time() - started >= self.duration:
                break

            # Benign clients arrive in bursts with idle gaps between them;
            # attackers hold a steady high rate. The shape of the inter-arrival
            # distribution is itself a detection signal.
            if self.burst and self._i and self._i % self.rng.randint(3, 8) == 0:
                time.sleep(self.rng.uniform(1.5, 5.0))
                next_at = time.time()

            code = send(self.base, self.api_key, self.next_query())
            self.codes[code] += 1
            self.sent += 1
            self._i += 1

            if interval:
                if self.pacing == "poisson":
                    step = self.rng.expovariate(1.0 / interval)
                else:
                    step = interval
                    if self.jitter:
                        step *= 1.0 + self.rng.uniform(-self.jitter, self.jitter)
                next_at += step
                delay = next_at - time.time()
                if delay > 0:
                    time.sleep(delay)
                else:
                    next_at = time.time()  # fell behind; do not build up debt


def split_campaign(args):
    """One attack stream divided across several API keys.

    This is the cheapest evasion of any per-key detector: buy K keys, send
    each a modest slice at an unremarkable rate. No member looks unusual on
    its own; the campaign only exists in aggregate.
    """
    k = args.split
    per_rate = (args.attacker_rate or 1.0) / k
    per_n = None if args.n is None else max(1, args.n // k)
    return [
        Client(args.base_url, "%s-%s" % (args.attacker_key, chr(ord("a") + r)),
               args.profile if args.profile in ATTACK_PROFILES
               else args.attacker_profile,
               args.seed + 7000 + r, rate=per_rate, n=per_n,
               duration=args.duration, jitter=args.attacker_jitter,
               pacing=args.attacker_pacing, index_offset=r, index_step=k,
               source=args.source)
        for r in range(k)
    ]


def build_clients(args):
    """Map a profile name onto the set of clients that profile implies."""
    if args.split > 1:
        return split_campaign(args)
    if args.profile == "mixed":
        clients = [
            Client(args.base_url, "user-%02d" % i, "benign", args.seed + i,
                   rate=args.rate or 1.0, duration=args.duration, n=args.n,
                   burst=True, jitter=args.jitter, pacing=args.pacing)
            for i in range(args.benign_clients)
        ]
        clients.append(
            Client(args.base_url, args.attacker_key, args.attacker_profile,
                   args.seed + 999, rate=args.attacker_rate,
                   duration=args.duration, n=args.attacker_n or args.n,
                   jitter=args.attacker_jitter, pacing=args.attacker_pacing,
                   source=args.source)
        )
        return clients

    default_key = args.attacker_key if args.profile in ATTACK_PROFILES else "user-00"
    key = args.api_key or default_key
    default_rate = 1.0 if args.profile in BENIGN_PROFILES else 20.0
    is_attack = args.profile in ATTACK_PROFILES
    return [Client(args.base_url, key, args.profile, args.seed,
                   rate=args.rate or default_rate, n=args.n,
                   duration=args.duration, burst=args.profile in BENIGN_PROFILES,
                   jitter=args.attacker_jitter if is_attack else args.jitter,
                   pacing=args.attacker_pacing if is_attack else args.pacing,
                   source=args.source, pool=args.pool)]


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--profile", default="benign",
                   choices=["benign", "random", "boundary", "sweep", "natural",
                            "real-benign", "real-harvest", "real-probe", "mixed"])
    p.add_argument("--n", type=int, help="requests per client")
    p.add_argument("--attacker-n", type=int,
                   help="override --n for the attacker in a mixed run")
    p.add_argument("--duration", type=float, help="seconds to run instead of --n")
    p.add_argument("--rate", type=float, help="requests/sec per benign client")
    p.add_argument("--attacker-rate", type=float, default=20.0)
    p.add_argument("--jitter", type=float, default=0.0,
                   help="fractional timing jitter for benign clients")
    p.add_argument("--attacker-jitter", type=float, default=0.0,
                   help="fractional timing jitter for the attacker; a patient "
                        "attacker uses this to defeat regularity detection")
    p.add_argument("--pacing", default="constant", choices=["constant", "poisson"],
                   help="inter-arrival model for benign clients")
    p.add_argument("--attacker-pacing", default="constant",
                   choices=["constant", "poisson"],
                   help="inter-arrival model for the attacker; poisson defeats "
                        "regularity-based detection")
    p.add_argument("--attacker-profile", default="boundary",
                   choices=list(ATTACK_PROFILES))
    p.add_argument("--attacker-key", default="attacker-01")
    p.add_argument("--api-key", help="override the key for single-profile runs")
    p.add_argument("--benign-clients", type=int, default=4)
    p.add_argument("--split", type=int, default=1,
                   help="divide the attack across this many API keys; each "
                        "member sends n/K queries at rate/K")
    p.add_argument("--source", default="mixed",
                   choices=["mixed", "reddit", "twitter", "yelp", "amazon", "imdb"],
                   help="real-text corpus for real-* profiles (mixed = all built)")
    p.add_argument("--pool", default="eval", choices=["calib", "eval"],
                   help="benign pool: calib to build a baseline, eval to test; "
                        "attackers always draw from the separate attack pool")
    p.add_argument("--seed", type=int, default=1)
    args = p.parse_args()

    if args.n is None and args.duration is None:
        args.n = 100

    # --- Refuse to generate against a server that is not ready: the run would
    # --- otherwise produce a log full of connection failures.
    health = args.base_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(health, timeout=5) as r:
            if not json.loads(r.read()).get("model_loaded"):
                print("Server is up but the model is not loaded yet.")
                return 2
    except Exception as e:
        print("Cannot reach %s: %s" % (args.base_url, e))
        return 2

    clients = build_clients(args)
    stop = threading.Event()
    limit_desc = ("n=%d" % args.n) if args.n else ("duration=%ss" % args.duration)
    print("profile=%s  clients=%d  %s" % (args.profile, len(clients), limit_desc))
    for c in clients:
        limit = ("n=%s" % c.n) if c.n else ("%ss" % c.duration)
        print("  %-14s %-9s %5.1f req/s  %s" % (c.api_key, c.profile, c.rate, limit))

    started = time.time()
    try:
        with ThreadPoolExecutor(max_workers=len(clients)) as pool:
            list(pool.map(lambda c: c.run(stop), clients))
    except KeyboardInterrupt:
        stop.set()
        print("\ninterrupted; stopping clients")
    elapsed = time.time() - started

    total = sum(c.sent for c in clients)
    codes = Counter()
    for c in clients:
        codes.update(c.codes)
    rate = total / elapsed if elapsed else 0.0
    print("\nsent %d requests in %.1fs (%.1f req/s aggregate)" % (total, elapsed, rate))
    print("status codes: %s" % dict(sorted(codes.items())))

    bad = sum(v for k, v in codes.items() if k != 200)
    if bad:
        print("WARNING: %d non-200 responses -- the log will be incomplete" % bad)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
