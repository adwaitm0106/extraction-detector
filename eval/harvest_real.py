"""Harvest real query/answer pairs from the victim, for the defence experiment.

Plays the one attacker the detector could not catch: a passive harvester
sending real text. Everything the API returns is saved, so the defence
experiment (eval/defend_real.py) can replay the same pairs under each defence
offline instead of re-querying the model once per defence.

Two sets are collected from disjoint pools of the real corpora:

    heldout   texts from the evaluation pools, labelled by the victim. Used
              only to measure how often a stolen copy agrees with the victim.
    harvest   texts from the attack pools, in the order the attacker sent
              them. This is the attacker's training data.

    python eval/harvest_real.py
    python eval/harvest_real.py --harvest 3000 --heldout 1000

Needs the API running and the corpora built. Writes
data/logs/steal_real_pairs.jsonl. Standard library only.
"""

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "traffic"))

from real_corpus import available_sources, load_pool  # noqa: E402

OUT = os.path.join(ROOT, "data", "logs", "steal_real_pairs.jsonl")


def call(base, key, text, retries=3):
    """One prediction. Returns (label, confidence), or (None, None) on failure."""
    body = json.dumps({"input": text}).encode("utf-8")
    for attempt in range(retries):
        req = urllib.request.Request(base.rstrip("/") + "/predict", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-Key", key)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
                return out.get("label"), out.get("confidence")
        except urllib.error.HTTPError as e:
            if e.code in (401, 422, 429):
                return None, None  # not transient; retrying will not help
        except Exception:
            pass
        time.sleep(0.5 * (attempt + 1))
    return None, None


def query_all(base, key, items, workers, label):
    """Label every (source, text) item with the victim, keeping input order."""
    t0 = time.time()
    results = [None] * len(items)

    def work(idx):
        src, text = items[idx]
        lab, conf = call(base, key, text)
        results[idx] = (src, text, lab, conf)
        return idx

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for _ in pool.map(work, range(len(items))):
            done += 1
            if done % 250 == 0 or done == len(items):
                print("  %-8s %5d / %d  (%.0fs)" % (label, done, len(items), time.time() - t0))
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--harvest", type=int, default=2000, help="attacker queries to collect")
    p.add_argument("--heldout", type=int, default=1000, help="held-out test texts")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--seed", type=int, default=21)
    p.add_argument("--out", default=OUT)
    args = p.parse_args()

    try:
        with urllib.request.urlopen(args.base_url + "/health", timeout=5) as r:
            if not json.loads(r.read()).get("model_loaded"):
                raise SystemExit("API is up but the model has not loaded yet.")
    except OSError as e:
        raise SystemExit("Cannot reach the API at %s: %s" % (args.base_url, e))

    sources = available_sources()
    if not sources:
        raise SystemExit("No corpora built. Run: python traffic/real_corpus.py")
    rng = random.Random(args.seed)

    # Held-out: an even share from every source's evaluation pool.
    per = args.heldout // len(sources)
    heldout = []
    for src in sources:
        texts = load_pool(src, "eval")
        heldout += [(src, t) for t in rng.sample(texts, min(per, len(texts)))]
    rng.shuffle(heldout)

    # Harvest: the attacker's corpus is every attack pool, in a shuffled order.
    attack = [(src, t) for src in sources for t in load_pool(src, "attack")]
    rng.shuffle(attack)
    harvest = attack[:args.harvest]

    overlap = {t for _, t in heldout} & {t for _, t in harvest}
    if overlap:
        raise SystemExit("held-out and harvest share %d texts; pools are not disjoint" % len(overlap))

    print("sources: %s" % ", ".join(sources))
    print("collecting %d held-out and %d harvest pairs" % (len(heldout), len(harvest)))
    rows_h = query_all(args.base_url, "defence-heldout-oracle", heldout, args.workers, "heldout")
    rows_a = query_all(args.base_url, "defence-harvester", harvest, args.workers, "harvest")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    failed = 0
    with open(args.out, "w", encoding="utf-8") as fh:
        for name, rows in (("heldout", rows_h), ("harvest", rows_a)):
            for i, (src, text, lab, conf) in enumerate(rows):
                if lab is None:
                    failed += 1
                    continue
                fh.write(json.dumps({"set": name, "i": i, "source": src, "text": text,
                                     "label": lab, "confidence": conf},
                                    ensure_ascii=False) + "\n")
    print("wrote %s  (%d failed requests skipped)" % (os.path.relpath(args.out, ROOT), failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
