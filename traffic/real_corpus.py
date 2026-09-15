"""Build pools of real text from public research datasets.

Downloads once, cleans, dedupes, and splits each source into three disjoint
pools by a stable hash of the text:

    calib   benign traffic the detector learns "normal" from
    eval    benign traffic the detector is tested on
    attack  text an attacker is allowed to use

A sentence lands in exactly one pool. The detector is never calibrated on text
it is later tested with, and an attacker never reuses a sentence a customer
sent. Assignment is by hash rather than by order, so a rebuild gives the same
split no matter what order the rows arrive in.

    python traffic/real_corpus.py
    python traffic/real_corpus.py --per-source 3000 --sources reddit twitter

Writes data/corpora/<source>.jsonl. Only this build step needs the `datasets`
package (traffic/requirements.txt). generate.py reads the cached files with the
standard library, so traffic generation still runs with nothing installed.

Licensing: these are research datasets. go_emotions and amazon_polarity are
Apache 2.0; tweet_eval, yelp_polarity and imdb carry their original research
terms. The text is cached locally and git-ignored, never committed.
"""

import argparse
import hashlib
import html
import json
import os
import re
import statistics
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS_DIR = os.path.join(ROOT, "data", "corpora")

SOURCES = {
    "reddit": {"repo": "google-research-datasets/go_emotions", "config": "simplified",
               "split": "train", "text": "text", "label": None, "stream": False,
               "domain": "social"},
    "twitter": {"repo": "cardiffnlp/tweet_eval", "config": "sentiment",
                "split": "train", "text": "text", "label": "label", "stream": False,
                "domain": "social"},
    "yelp": {"repo": "fancyzhx/yelp_polarity", "config": None, "split": "train",
             "text": "text", "label": "label", "stream": True, "domain": "reviews"},
    "amazon": {"repo": "fancyzhx/amazon_polarity", "config": None, "split": "train",
               "text": "content", "label": "label", "stream": True, "domain": "reviews"},
    # imdb's train split is sorted by label, so it is loaded whole and shuffled
    # rather than streamed; a streamed prefix would be all negative reviews.
    "imdb": {"repo": "stanfordnlp/imdb", "config": None, "split": "train",
             "text": "text", "label": "label", "stream": False, "domain": "movies"},
}

# Cumulative upper bounds on hash % 100. 40% calib, 40% eval, 20% attack.
POOLS = (("calib", 40), ("eval", 80), ("attack", 100))

# Long reviews are sent the way an analytics client would send them: a leading
# snippet of whole sentences. Keeps requests realistic and well inside the API's
# 2000-character limit.
MAX_CHARS = 300
MIN_WORDS = 3

_BR = re.compile(r"<br\s*/?>", re.I)
_WS = re.compile(r"\s+")
_SENT = re.compile(r"(?<=[.!?])\s+")


def clean(text):
    if not isinstance(text, str):
        return None
    t = html.unescape(text)
    t = _BR.sub(" ", t)
    t = t.replace("\\n", " ").replace('\\"', '"')
    t = _WS.sub(" ", t).strip()
    if len(t) > MAX_CHARS:
        out = ""
        for s in _SENT.split(t):
            if out and len(out) + 1 + len(s) > MAX_CHARS:
                break
            out = (out + " " + s).strip()
        t = out or t
        if len(t) > MAX_CHARS:
            t = t[:MAX_CHARS].rsplit(" ", 1)[0]
    if len(t.split()) < MIN_WORDS:
        return None
    return t


def pool_for(text):
    h = int(hashlib.sha1(text.lower().encode("utf-8")).hexdigest()[:8], 16) % 100
    for name, upper in POOLS:
        if h < upper:
            return name
    return POOLS[-1][0]


# --- Reading. Standard library only, so generate.py can import this without
# --- `datasets` installed.
def corpus_path(source):
    return os.path.join(CORPUS_DIR, source + ".jsonl")


def available_sources():
    if not os.path.isdir(CORPUS_DIR):
        return []
    return sorted(f[:-6] for f in os.listdir(CORPUS_DIR) if f.endswith(".jsonl"))


def load_pool(source, pool):
    """All texts from one source's pool. pool=None returns every pool."""
    path = corpus_path(source)
    if not os.path.exists(path):
        raise FileNotFoundError(
            "No corpus for %r at %s. Build it first:\n"
            "  python traffic/real_corpus.py --sources %s" % (source, path, source))
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                if pool is None or r["pool"] == pool:
                    out.append(r["text"])
    if not out:
        raise ValueError("Corpus %r has no texts in pool %r" % (source, pool))
    return out


def perturb_query(text, rng, vocab):
    """One small edit to a real sentence: the boundary-probing move on real text.

    Hold almost everything fixed and change one token, to find where the
    model's label flips. `vocab` supplies plausible substitute words drawn from
    the attacker's own corpus, so the edits stay natural-looking.
    """
    words = text.split()
    if not words:
        return text
    i = rng.randrange(len(words))
    mode = rng.random()
    if mode < 0.4 and vocab:
        words[i] = rng.choice(vocab)
    elif mode < 0.7 and len(words) > MIN_WORDS:
        words.pop(i)
    elif mode < 0.9:
        words.insert(i, words[i])
    else:
        w = words[i]
        j = rng.randrange(len(w))
        words[i] = w[:j] + rng.choice("abcdefghijklmnopqrstuvwxyz") + w[j + 1:]
    return " ".join(words)


# --- Building. Needs `datasets`; imported inside so reading never does. ---
def build_source(name, per_source, seed):
    from datasets import load_dataset

    cfg = SOURCES[name]
    if cfg["stream"]:
        ds = load_dataset(cfg["repo"], cfg["config"], split=cfg["split"], streaming=True)
        ds = ds.shuffle(seed=seed, buffer_size=20000)
    else:
        ds = load_dataset(cfg["repo"], cfg["config"], split=cfg["split"]).shuffle(seed=seed)

    seen, rows, scanned = set(), [], 0
    for row in ds:
        scanned += 1
        if scanned > per_source * 6:
            break
        t = clean(row.get(cfg["text"]))
        if not t or t.lower() in seen:
            continue
        seen.add(t.lower())
        rows.append({"text": t, "pool": pool_for(t), "source": name,
                     "domain": cfg["domain"],
                     "label": row.get(cfg["label"]) if cfg["label"] else None})
        if len(rows) >= per_source:
            break
    return rows, scanned


def write_rows(name, rows):
    os.makedirs(CORPUS_DIR, exist_ok=True)
    path = corpus_path(name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, path)
    return path


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sources", nargs="+", default=list(SOURCES), choices=list(SOURCES))
    p.add_argument("--per-source", type=int, default=6000)
    p.add_argument("--seed", type=int, default=13)
    p.add_argument("--force", action="store_true", help="rebuild corpora that already exist")
    args = p.parse_args()

    print("%-8s %6s %7s %6s %6s %6s %8s  %s" % (
        "source", "kept", "scanned", "calib", "eval", "attack", "med_len", "labels"))
    print("-" * 78)
    all_texts = {}
    for name in args.sources:
        if os.path.exists(corpus_path(name)) and not args.force:
            rows = [json.loads(l) for l in open(corpus_path(name), encoding="utf-8") if l.strip()]
            scanned, note = "cached", ""
        else:
            t0 = time.time()
            rows, scanned = build_source(name, args.per_source, args.seed)
            write_rows(name, rows)
            note = "  (%.0fs)" % (time.time() - t0)
        pools = Counter(r["pool"] for r in rows)
        med = statistics.median(len(r["text"]) for r in rows) if rows else 0
        labels = Counter(r["label"] for r in rows if r["label"] is not None)
        lab = ", ".join("%s:%d%%" % (k, round(100 * v / sum(labels.values())))
                        for k, v in sorted(labels.items())) if labels else "n/a"
        print("%-8s %6d %7s %6d %6d %6d %8.0f  %s%s" % (
            name, len(rows), scanned, pools["calib"], pools["eval"], pools["attack"],
            med, lab, note))
        all_texts[name] = {r["text"].lower() for r in rows}

    # Pools are disjoint within a source by construction. Across sources the
    # same text could in principle appear twice; report it rather than assume.
    names = sorted(all_texts)
    overlap = sum(len(all_texts[a] & all_texts[b])
                  for i, a in enumerate(names) for b in names[i + 1:])
    print("\ncross-source duplicate texts: %d" % overlap)
    print("corpora in %s" % CORPUS_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
