"""Measure the query-budget defence against a STRONG attacker.

eval/defend_real.py answers "does a budget help?" using a cheap TF-IDF student.
That understates the threat: a real attacker fine-tunes a pretrained language
model, not a bag-of-words classifier. This script re-runs the same question
with that stronger attacker, on the exact same harvested pairs, so the two
results are directly comparable.

The student is distilbert-base-uncased (public pretrained weights from
Hugging Face, downloaded once) with a fresh classification head, fine-tuned on
whatever the attacker harvested. It never sees the victim model's own
weights, only its answers, the way a real attacker would build a copy. This is
a distillation attack: training a small model to imitate a larger one's
outputs.

    python eval/defend_real_strong.py
    python eval/defend_real_strong.py --sizes 50 200 800 2000 --epochs 3

Needs eval/harvest_real.py to have been run first (reads the same
data/logs/steal_real_pairs.jsonl as eval/defend_real.py) and needs torch and
transformers, which api/requirements.txt already installs.

Fine-tuning on CPU is slow. Each size trains one model once (no repeats, unlike
the TF-IDF experiment); budget for several minutes per size.

Writes eval/results/defences_real_strong.json,
eval/results/defences_real_strong.md and
eval/figures/defence_budget_fidelity_strong.png.
"""

import argparse
import json
import os
import random
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PAIRS = os.path.join(ROOT, "data", "logs", "steal_real_pairs.jsonl")
RESULTS = os.path.join(HERE, "results")
FIGURE = os.path.join(HERE, "figures", "defence_budget_fidelity_strong.png")

MODEL_NAME = "distilbert-base-uncased"
MAX_LEN = 64
BATCH = 16
EPOCHS_DEFAULT = 3
LR = 2e-5
SIZES_DEFAULT = (50, 200, 800, 2000)


def load_pairs(path):
    heldout, harvest = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                (heldout if r["set"] == "heldout" else harvest).append(r)
    harvest.sort(key=lambda r: r["i"])
    return heldout, harvest


def pct(x):
    return "%.1f%%" % (100 * x)


def train_and_eval(texts, labels, heldout_texts, heldout_labels, epochs, seed, log_prefix=""):
    """Fine-tune distilbert-base-uncased on (texts, labels); return held-out accuracy.

    A fresh model per call: the point is what an attacker gets from scratch
    with N pairs, not a model that has seen more data than it should have.
    """
    import torch
    from torch.utils.data import DataLoader, Dataset
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    torch.manual_seed(seed)
    label_names = sorted(set(labels) | set(heldout_labels))
    to_id = {name: i for i, name in enumerate(label_names)}

    tok = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=len(label_names))
    model.train()

    class PairSet(Dataset):
        def __init__(self, texts, labels):
            self.enc = tok(list(texts), truncation=True, padding="max_length",
                           max_length=MAX_LEN, return_tensors="pt")
            self.labels = torch.tensor([to_id[lbl] for lbl in labels])

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, i):
            item = {k: v[i] for k, v in self.enc.items()}
            item["labels"] = self.labels[i]
            return item

    loader = DataLoader(PairSet(texts, labels), batch_size=BATCH, shuffle=True,
                        generator=torch.Generator().manual_seed(seed))
    opt = torch.optim.AdamW(model.parameters(), lr=LR)

    t0 = time.time()
    for epoch in range(epochs):
        total_loss = 0.0
        for batch in loader:
            opt.zero_grad()
            out = model(**batch)
            out.loss.backward()
            opt.step()
            total_loss += out.loss.item()
        print("%s  epoch %d/%d  mean loss %.4f  (%.0fs elapsed)"
              % (log_prefix, epoch + 1, epochs, total_loss / max(1, len(loader)), time.time() - t0))

    model.eval()
    enc = tok(list(heldout_texts), truncation=True, padding=True, max_length=MAX_LEN,
             return_tensors="pt")
    with torch.no_grad():
        preds = model(**enc).logits.argmax(dim=-1).tolist()
    id_to_label = {v: k for k, v in to_id.items()}
    predicted = [id_to_label[p] for p in preds]
    acc = sum(p == y for p, y in zip(predicted, heldout_labels, strict=True)) / len(heldout_labels)
    return acc, time.time() - t0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pairs", default=PAIRS)
    p.add_argument("--sizes", type=int, nargs="+", default=list(SIZES_DEFAULT))
    p.add_argument("--epochs", type=int, default=EPOCHS_DEFAULT)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        raise SystemExit("torch/transformers not installed. Run:\n"
                         "  .venv/Scripts/python.exe -m pip install -r api/requirements.txt") from None
    if not os.path.exists(args.pairs):
        raise SystemExit("No pairs at %s. Run eval/harvest_real.py first." % args.pairs)

    heldout, harvest = load_pairs(args.pairs)
    majority_label, majority_n = Counter(r["label"] for r in heldout).most_common(1)[0]
    majority = majority_n / len(heldout)
    ho_texts = [r["text"] for r in heldout]
    ho_labels = [r["label"] for r in heldout]

    print("held-out %d texts, harvest pool %d pairs, always guessing %s scores %s"
          % (len(heldout), len(harvest), majority_label, pct(majority)))
    print("student: %s, %d epochs, max_len %d, batch %d, lr %g\n"
          % (MODEL_NAME, args.epochs, MAX_LEN, BATCH, LR))

    curve = []
    for size in sorted(set(s for s in args.sizes if s <= len(harvest))):
        rng = random.Random(args.seed * 1000 + size)
        sample = rng.sample(harvest, size)
        texts = [r["text"] for r in sample]
        labels = [r["label"] for r in sample]
        acc, secs = train_and_eval(texts, labels, ho_texts, ho_labels, args.epochs,
                                   seed=args.seed, log_prefix="  [%d pairs]" % size)
        curve.append({"pairs": size, "fidelity": acc, "train_seconds": secs})
        print("  %5d pairs  fidelity %s  (%.0fs)\n" % (size, pct(acc), secs))

    results = {"heldout": len(heldout), "harvest_pool": len(harvest),
               "majority_baseline": majority, "model": MODEL_NAME,
               "epochs": args.epochs, "max_len": MAX_LEN, "batch": BATCH, "lr": LR,
               "curve": curve}
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "defences_real_strong.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    md = ["Stolen copy agreement with the victim on %d held-out real texts, using a "
         "fine-tuned %s as the attacker's student (not the TF-IDF student used "
         "elsewhere). Always guessing the most common label scores %s." % (
             len(heldout), MODEL_NAME, pct(majority)), "",
         "| Pairs harvested | Copy agreement (DistilBERT student) | Training time |",
         "|---|---|---|"]
    for row in curve:
        md.append("| %d | %s | %.0fs |" % (row["pairs"], pct(row["fidelity"]), row["train_seconds"]))
    text = "\n".join(md) + "\n"
    with open(os.path.join(RESULTS, "defences_real_strong.md"), "w", encoding="utf-8") as fh:
        fh.write(text)

    # Overlay against the TF-IDF curve, if it has been generated, so the two
    # attackers are visible on one chart.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7.5, 4.2))
        xs = [r["pairs"] for r in curve]
        ys = [100 * r["fidelity"] for r in curve]
        ax.plot(xs, ys, marker="o", color="#7b2d8e", label="DistilBERT student (strong attacker)")

        tfidf_path = os.path.join(RESULTS, "defences_real.json")
        if os.path.exists(tfidf_path):
            with open(tfidf_path, encoding="utf-8") as fh:
                tf = json.load(fh)
            txs = [r["pairs"] for r in tf["curve"]]
            tys = [100 * r["soft"]["mean"] for r in tf["curve"]]
            ax.plot(txs, tys, marker="s", color="#2f5bd0", linestyle="--",
                    label="TF-IDF student (weak attacker)")

        ax.axhline(100 * majority, color="#888", linestyle=":", linewidth=1,
                   label="always guess %s (%.0f%%)" % (majority_label.lower(), 100 * majority))
        ax.set_xscale("log")
        ax.set_xlabel("query/answer pairs the attacker collected (log scale)")
        ax.set_ylabel("copy agrees with victim (%)")
        ax.set_title("A capable attacker learns faster from the same harvested pairs",
                     fontsize=10)
        ax.legend(fontsize=8, loc="lower right")
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
    print("wrote eval/results/defences_real_strong.json and eval/results/defences_real_strong.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
