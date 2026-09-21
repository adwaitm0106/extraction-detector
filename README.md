# Extraction Detector

[![tests](https://github.com/adwaitm0106/extraction-detector/actions/workflows/tests.yml/badge.svg)](https://github.com/adwaitm0106/extraction-detector/actions/workflows/tests.yml)

Catching people who try to steal your ML model by asking it a lot of questions.

## What this is about

If you sell access to a model through an API, someone can copy it without ever
breaking in. They just use it. They send inputs, save the answers, and train
their own model on those pairs. At the end they have a decent copy of the thing
you paid to build, and your logs show nothing but a customer using the product.

Most people defend against this with rate limits. That works fine if the
attacker is in a hurry. It does nothing if they're patient. Someone sending one
query a second looks exactly like a normal customer, and in a week they have
plenty of data.

So this project doesn't look at how *much* someone queries. It looks at *what*
they ask. Copying a model means covering the input space in an organised way,
and organised queries look different from real ones. Different vocabulary,
more repetition, more queries sitting right on the edge where the model can't
decide. Those patterns don't go away when you slow down.

And it doesn't stop at noticing. Once a key is flagged, the API starts
answering it with HTTP 429 and the attacker's harvest stops.

**Who'd use this:** a team running a paid inference API. Sentiment,
moderation, classification, anything sold per call.

**What it costs to get wrong:** if you wrongly flag a real customer, they get
throttled or cut off, and that's a support ticket and maybe a lost account. So
the detector never just says "attacker". It prints which signals fired, how far
off normal they were, and a plain-English reason for each one. And it won't
flag anyone on a single signal alone.

## At a glance

- **It catches attackers who probe the model.** On real text from five public
  datasets it caught every boundary-probing attacker (3 of 3) and wrongly
  flagged none of 10 real customers, including two sending a kind of text it
  had never seen.
- **It can't catch passive harvesting, and the repo shows why.** A harvester
  sending ordinary text looks statistically the same as a real customer, so 0
  of 7 harvesting keys were caught.
- **So two defences were added, then stress-tested against a real attacker.**
  Hiding the model's confidence made no difference, because this model is
  almost always sure of itself. A query budget of 50 per key holds a weak
  (TF-IDF) attacker to 55.9% agreement, barely above guessing, but a real
  attacker fine-tuning a small pretrained language model on the same 50
  pairs gets 65.1%, and only needs 200 pairs across 4 keys to reach 81.5%.
- **It doesn't depend on this one model being overconfident.** Swapping the
  victim for a very different model (three labels, median confidence 0.84
  instead of 0.998) gave the identical result, and removing the confidence
  signals entirely loses no attackers. Two content signals do the work.
- **An attacker who knows how it works gets past it.** A boundary prober using
  the standard countermeasures from the first round, with no feedback at all,
  was never flagged in 3 of 3 trials. Hiding the detector's reasons doesn't
  change that.
- **It's fast enough not to matter.** About 20,000 requests a second, over a
  thousand times faster than the model it protects. Benchmarking it found and
  fixed a bug that made live alerting fall behind as the log grew.
- **Everything is reproducible.** One command rebuilds the data, one reruns each
  experiment, and 62 tests run on every push.

## What's in here

```
api/        the "victim" API - a sentiment model that logs every request,
            with optional confidence hiding and per-key query budgets
traffic/    fake traffic: normal customers and several kinds of attacker
detector/   detection - features, calibration, scoring, enforcement, dashboard
eval/       measuring the detector, the stolen-copy and defence experiments,
            signal ablation, a second victim model, the adaptive attacker,
            the throughput benchmark, and the charts
demo/       one script that runs the whole story end to end, plus a
            stage-by-stage walkthrough of what it prints
tests/      the automated test suite, run on every push by GitHub Actions
```

## Run it yourself

You need Python 3.11 or newer and about 10 minutes, most of it downloading the
model.

**Everything below assumes you're inside the `extraction-detector` folder.**
All the paths are relative. If you run these from the parent folder you'll get
confusing errors like `No module named 'api'` or `No baseline at
thresholds.json`. The real problem is just that you're in the wrong directory.

### Setup

```bash
git clone https://github.com/adwaitm0106/extraction-detector.git
cd extraction-detector
python -m venv .venv
```

Install (about 250 MB, CPU-only PyTorch):

```bash
.venv/Scripts/python.exe -m pip install -r api/requirements.txt
```

On Mac or Linux, swap `.venv/Scripts/python.exe` for `.venv/bin/python`
everywhere in this README.

### The fastest way to see it work

One command runs the whole thing. It starts the API, learns what normal looks
like, sends benign traffic, then sends an attacker, alerts on it live, and cuts
it off:

```powershell
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```

Takes a little under 3 minutes the first time. There's a `demo/run_demo.sh`
for Mac and Linux. It cleans up after itself, including if you hit Ctrl+C.

**What you should see:**

1. `API ready: model_loaded=true` means the model has loaded
2. A calibration phase with four fake customers. This is the detector learning
   what normal traffic looks like
3. **PHASE 1** in green: normal customers querying. You should see
   `30 requests scored - all clean` and **no alerts**
4. **PHASE 2** in red: the attacker starts. About 20 seconds later a red
   `[ALERT] EXTRACTION SUSPECTED` line appears with the signals that fired and
   a `why:` line explaining them, then a yellow `[BLOCK]` line
5. The attacker's own tally, something like `status codes: {200: 37, 429: 23}`.
   The 200s got through before the block, the 429s didn't
6. A results table, then everything shuts down

If Phase 1 stays quiet and Phase 2 alerts and blocks, it's working.

`demo/terminal_walkthrough.md` has the real output from a full run, stage by
stage, with a note on what each stage proves. Useful if you want to see what
should happen before you run it, or if something looks different on your
machine. `demo/screenshots/` has the same thing rendered as images.

### Checking it by hand

Start the API in one terminal:

```bash
.venv/Scripts/python.exe -m uvicorn api.main:app --port 8000
```

Wait for it to finish loading, then in a second terminal:

```bash
curl.exe -s http://127.0.0.1:8000/health
```

You want `{"status":"ok","model_loaded":true}`. If `model_loaded` is `false`,
it's still downloading the model, give it a minute.

> **Windows note:** in PowerShell, `curl` is not curl. It's an alias for
> `Invoke-WebRequest` and it will reject these flags. Type `curl.exe` with the
> `.exe` on the end. In Git Bash, plain `curl` is fine.

Send one request:

```bash
curl.exe -s -X POST http://127.0.0.1:8000/predict -H "Content-Type: application/json" -H "X-API-Key: demo-key-1" -d "{\"input\":\"This movie was absolutely fantastic.\"}"
```

You should get back something like
`{"label":"POSITIVE","confidence":0.9998722076416016}`, and a new line should
appear in `data/logs/requests.jsonl`.

To check nothing's broken:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
```

That starts its own server, runs 12 checks, and shuts down. You want
`All 12 checks passed.` There's also `api/test_api.py`, which throws 36 nasty
inputs at a running API (empty strings, emoji, null bytes, 10,000 characters,
50 requests at once) and checks it never falls over.

### Doing it step by step

If you'd rather run the pieces yourself, with the API already running:

```bash
# 1. Generate normal traffic and save it separately. This is what the detector
#    learns "normal" from, so it must NOT contain any attack traffic.
for i in 0 1 2 3; do
  .venv/Scripts/python.exe traffic/generate.py --profile benign --n 45 \
    --rate 3 --jitter 0.5 --api-key "cal-user-$i" --seed $((100+i)) &
done; wait
mv data/logs/requests.jsonl data/logs/benign_calib.jsonl

# 2. Learn the baseline
.venv/Scripts/python.exe detector/baseline.py \
  --log data/logs/benign_calib.jsonl --out thresholds.json

# 3. Now traffic to actually test on - a customer and an attacker
.venv/Scripts/python.exe traffic/generate.py --profile benign --n 45 \
  --rate 3 --jitter 0.5 --api-key customer-0 --seed 200
.venv/Scripts/python.exe traffic/generate.py --profile boundary --n 45 \
  --rate 1.0 --attacker-pacing poisson --api-key L3-poisson --seed 303

# 4. Score it
.venv/Scripts/python.exe detector/detector.py --log data/logs/requests.jsonl
.venv/Scripts/python.exe eval/evaluate.py --log data/logs/requests.jsonl \
  --attack-prefix L0- L1- L2- L3- L4- L5-
```

`detector/detector.py` and `detector/baseline.py` are the entry points. The
code behind them lives in `score.py` and `calibrate.py`; either name works and
they take the same arguments.

**Don't reduce the number of clients in step 1.** The detector works on windows
of 30 requests and needs at least 5 windows to learn anything. Four clients at
45 requests each gives 8. One client at 45 gives 2, and calibration will refuse
to run.

### Watching it live, and cutting attackers off

`--watch` polls the log every few seconds and alerts as traffic arrives. It reads
only the lines added since the last poll and rescores only the clients that sent
them, so a cycle stays cheap however long the API has been running (42 ms on a
100,000-request log, against 3 seconds for a full rescan):

```bash
.venv/Scripts/python.exe detector/detector.py --log data/logs/requests.jsonl --watch
```

Add `--enforce` and flagged keys get written to `blocked.json`. The API reads
that file and answers every request from a blocked key with HTTP 429:

```bash
.venv/Scripts/python.exe detector/detector.py --log data/logs/requests.jsonl --watch --enforce
```

An alert looks like this:

```
[ALERT 20:19:34] EXTRACTION SUSPECTED  api_key=L3-poisson  flags=3/10  requests=45  signals: herdan_c(9.1), near_dup_rate(5.1), token_entropy_norm(3.7)
  why: uses an unusually narrow vocabulary; sends many near-identical queries; word choice is unnaturally uniform or unnaturally skewed
[BLOCK 20:19:34] api_key=L3-poisson now receives 429 on every request
```

The detector and the API never talk to each other directly. The blocklist is
just a file, so either side can restart without the other noticing, and if the
detector isn't running nobody is blocked.

There's a web dashboard too:

```bash
.venv/Scripts/python.exe -m uvicorn detector.dashboard:app --port 8050
```

Then open <http://127.0.0.1:8050>. It shows every client, whether it's flagged,
and which signals fired. It only reads the log, so it's safe to leave running
during an experiment.

### Automated tests

There's a suite of 62 tests that runs on every push through GitHub Actions, on
Python 3.11 and 3.12. It covers the ten signals, calibration and the flag rule,
the blocklist, the live log reader, the corpus pools, the defences, and the
whole API: auth, validation, logging, blocking, budgets and response modes.

It doesn't need torch or the model download. The API tests run against a tiny
stand-in model (`MODEL_STUB=1`), so the whole suite finishes in about a second.

```bash
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
.venv/Scripts/python.exe -m pytest
```

The stand-in model exists only for testing. It isn't a sentiment model, and none
of the results in this README come from it.

## Things that will trip you up

- **Wrong folder.** Every path is relative to `extraction-detector/`. From
  anywhere else you get errors that never mention directories.
- **`curl` in PowerShell isn't curl.** Use `curl.exe`.
- **The API writes the log, not the traffic generator.** To put the log
  somewhere else, set `LOG_PATH` on the *server* before starting it. Setting it
  on the generator does nothing, it's silently ignored.
- **Nothing works until you calibrate.** `detector.py` needs `thresholds.json`,
  which `baseline.py` creates. Run it on normal traffic only.
- **A client needs 30 requests before it can be judged.** Below that it shows
  as `insufficient`. Live, that's about 20 seconds before the first verdict.
- **`--api-key` is ignored with `--split` or `--profile mixed`.** Those modes
  name their own keys, based on `--attacker-key`.
- **Calibrate at the same pace you'll judge.** The burstiness signal shifts
  with how fast the calibration clients ran. We learned this the hard way: the
  demo used to calibrate at 6 requests a second and then judge customers at
  1.5, and those customers came out at z=11 on burstiness. Same rate on both
  sides and they dropped to zero.
- **A stale `blocked.json` blocks people.** If you ran with `--enforce` and a
  key got flagged, it stays blocked until you delete the file or rerun the
  detector. The demo script removes it on exit; if you're running things by
  hand, remember to.
- **There's no Docker setup.** There was one, but it never got verified on a
  real machine, so it was taken out rather than shipped untested. It's in the
  git history at commit `6ef1a8f` if you want to revive it.

## How it works

```
traffic/generate.py  ──HTTP──▶  api/main.py  ──▶  data/logs/requests.jsonl
 normal + attacker               DistilBERT              one line per request
                                     ▲                            │
                                     │ 429 if key         ┌───────┴────────┐
                                     │ is blocked         ▼                ▼
                                 blocked.json ◀── detector/detector.py   dashboard
                                                  scores + alerts
                                                        ▲
                                     detector/baseline.py ─ thresholds.json
                                     learns from normal traffic only
```

**The API** is a sentiment classifier (DistilBERT fine-tuned on SST-2). It
loads once at startup and writes one JSON line per successful request: time,
API key, the input, the predicted label, the confidence, and how long inference
took. Failed requests aren't logged. Before answering, it checks whether the
key is in `blocked.json` and returns 429 if so.

**The traffic generator** gives each fake client its own API key, which is how
we know afterwards who was who. A client is either a normal customer or an
attacker doing one of several things: random word salad, probing right around
the decision boundary, marching through a template grid, or sending
natural-looking sentences that systematically cover the space. Attackers can
also slow down, add random delays, space requests the way a real person would,
or spread the work across several API keys.

**The detector** looks at each client in windows of 30 requests and measures
ten things:

| What it measures | Why it helps |
|---|---|
| duplicate and near-duplicate rate | probing repeats itself; random sampling never does |
| vocabulary richness, token entropy | generated text uses a narrow or oddly even vocabulary |
| length variation, template repetition | grid-marching produces near-identical structures |
| low-confidence share, 10th-percentile confidence | probing clusters where the model is unsure |
| burstiness of arrival times | people work in bursts; scripts don't |
| label balance | systematic coverage gives an unnaturally even split |

None of these depend on how many requests someone sends. That's deliberate.
Volume is the obvious signal and the easiest one to dodge.

**Calibration** takes normal traffic and works out a typical value and a spread
for each of the ten measures. Scoring then asks, for each client, how far from
normal each measure is. Two or more measures more than 3.5 standard deviations
out, and the client gets flagged. Each client is judged on its worst window, so
an attacker can't hide a probing burst inside a lot of innocent-looking padding.

**One more piece:** `detector/campaign.py` looks for an attack split across
several API keys. It finds pairs of keys that are much more alike than normal
pairs are, groups them, then scores the group's combined traffic. It only calls
something a campaign if both the grouping *and* the combined traffic look wrong.

### Why the results aren't rigged

The obvious way to cheat at this is to tune the detector on the same traffic
you test it on. We didn't:

- Calibration only ever sees **normal** traffic. The detector never looks at an
  attack while learning, so it can't memorise the specific attacks in this repo.
- The clients used for calibration and the clients used for testing are
  **different clients with different random seeds**.
- Only two numbers per measure are learned, a middle and a spread. There are
  no weights to overfit.
- The two decision numbers (3.5 standard deviations, at least 2 signals) were
  picked up front from basic statistics, not tuned until the results looked good.

## Results on real text

The synthetic results further down look great, and that's the problem. The fake
customers and the fake attackers came out of the same template generator, so
they were easy to tell apart. So the whole evaluation was rerun on real text.

**The data.** 30,000 real texts from five public research datasets, 6,000 from
each: Reddit comments (`go_emotions`), tweets (`tweet_eval`), Yelp reviews,
Amazon reviews and IMDB reviews. Nothing was scraped. Every text goes into
exactly one of three pools, decided by a hash of its content: 40% for building
the baseline, 40% for testing, and 20% that only attackers may use. Checked
after building: not a single text is shared between any two pools, across all
five sources.

**The setup.** The baseline was learned from 8 real customers, two each sending
Reddit comments, tweets, Yelp reviews and Amazon reviews. Then 10 new customers
were tested: two per source again, plus two sending IMDB reviews, a kind of
text the baseline had never seen. Attackers ran at about one request a second
with human-like timing and only used the attack pool. 1,050 requests in total.
The text is real. The timing still comes from the generator's model of how
people behave, which hasn't been checked against real API logs.

| Client | What it did | Caught? |
|---|---|---|
| `atk-probe-twitter` | small edits to a few real tweets, hunting the decision boundary | yes (3 signals) |
| `atk-probe-yelp` | the same thing on real Yelp reviews | yes (2 signals) |
| `atk-template-boundary` | the old synthetic attacker, for reference | yes (2 signals) |
| `atk-harvest-yelp` | walked through real Yelp reviews, never repeating | **no** |
| `atk-harvest-mixed` | walked through all five sources, never repeating | **no** |
| `atk-harvest-split-a` to `e` | one harvest split across 5 keys | **no, 0 of 5** |
| 8 customers, seen sources | real Reddit, tweet, Yelp and Amazon traffic | 0 false alarms |
| 2 customers, unseen source | real IMDB traffic | 0 false alarms |

**3 of 10 attackers caught. 0 of 10 real customers wrongly flagged.**

![Signals fired per client on real text](eval/figures/real_flags_per_client.png)

That's a far worse detection number than the synthetic 10 of 10, and it's the
more useful one. Here's why the harvesters got through. These are the median
values for each group, next to the centre of the baseline:

| Signal | Baseline | Customers | Probers | Harvesters |
|---|---|---|---|---|
| near-duplicate rate | 0.350 | 0.383 | **1.000** | 0.000 |
| vocabulary richness (`herdan_c`) | 0.892 | 0.886 | **0.710** | 0.904 |
| exact repeat rate | 0.200 | 0.200 | 0.033 | 0.000 |
| word entropy | 0.916 | 0.922 | 0.946 | 0.891 |
| 10th percentile confidence | 0.938 | 0.946 | 0.981 | 0.941 |

Probers stand out enormously. Nearly every query is a near-copy of another, and
they reuse a tiny vocabulary. Harvesters don't stand out at all. Their
vocabulary, word choice and model confidence sit right where real customers
are, because a harvester sending random real Yelp reviews is doing exactly what
a real Yelp analytics customer does. The one difference is that it never
repeats a query, and that only reached z=2.8, under the 3.5 cutoff.

![Where each group lands on four signals](eval/figures/real_signal_separation.png)

Each dot is one 30-request window from one client. The shaded band is the zone
where a signal doesn't fire. Probers land well outside it on near-duplicates and
vocabulary. Harvesters sit inside it on every panel, right alongside the
customers. Confidence doesn't separate anyone on real text.

I didn't lower the cutoff to catch them, for two reasons. It would mean tuning
the rule to this result, which is the exact thing the design avoids. And the
"never repeats" gap isn't real evidence anyway. It only exists because the
customer generator assumes people re-ask 20% of the time, and nobody has
measured that.

So the honest conclusion: **looking at the shape of one key's queries catches
attackers who probe the model, but it cannot catch passive harvesting of
normal-looking text.** That attack needs a different kind of defence, such as
returning labels without confidence scores, per-account query budgets, or
looking for coverage patterns across many accounts at once.

Run it yourself. The API needs to be running for the experiment step.

```bash
.venv/Scripts/python.exe -m pip install -r traffic/requirements.txt
.venv/Scripts/python.exe traffic/real_corpus.py
.venv/Scripts/python.exe eval/run_real_experiment.py
.venv/Scripts/python.exe eval/diagnose_real.py
```

Building the corpora downloads the datasets and took about two and a half
minutes here. The experiment took about five and a half. Results land in
`eval/results/`.

## Defending against harvesting

The detector can't see a harvester, so the next question is whether anything
else stops one. Two defences were added to the API and measured against a
real-text harvester:

- **Hide the confidence.** `RESPONSE_MODE=label` returns only the label, and
  `RESPONSE_MODE=rounded` rounds the confidence to one decimal place.
- **Cap each key.** `QUERY_BUDGET=50` serves 50 requests per API key and
  answers the rest with HTTP 429. Malformed requests don't count against it.

Both are off by default, and both are set as environment variables when you
start the API.

To measure them, the attacker was played for real. 2,000 real texts from the
attack pool were sent to the victim, the answers saved, and a stolen copy
trained on them (TF-IDF plus logistic regression, weighted by the victim's
confidence whenever the response includes one). The copy is then scored on
1,000 held-out real texts it never saw, by how often it agrees with the
victim. Always guessing the most common label scores 54.1%, so that's the
floor. Every defence is replayed on the same saved answers, through the same
function the API calls, so they're all compared on identical data.

**Hiding the confidence does nothing here.**

| What the API returns | Stolen copy agrees with victim |
|---|---|
| label and confidence | 72.5% |
| label and rounded confidence | 72.5% |
| label only | 72.6% |

This model is almost always more than 99% sure of itself, so its confidence
carries almost no extra information for the attacker. On a model that's often
unsure it might matter more. On this one it doesn't.

**Budgets work, until the attacker gets more keys.**

| Pairs the attacker collected | Stolen copy agrees with victim |
|---|---|
| 25 | 53.0% |
| 50 | 55.9% |
| 100 | 59.6% |
| 400 | 65.1% |
| 2,000 | 72.5% |

A budget of 50 per key holds a one-key harvester to 55.9%, barely above
guessing. But the budget is per key:

| Budget per key | Keys | Stolen copy agrees with victim |
|---|---|---|
| 50 | 1 | 55.9% |
| 50 | 5 | 64.0% |
| 50 | 20 | 69.7% |

With 20 keys the attacker gets back most of what an unlimited attacker gets
(69.7% against 72.5%). So a budget only protects the model if keys are hard to
get, meaning tied to a verified account or a payment method. That's a business
decision, not a code change.

![Stolen copy agreement against the number of pairs harvested](eval/figures/defence_budget_fidelity.png)

Run it yourself. The API needs to be running for the harvest step.

```bash
.venv/Scripts/python.exe -m pip install -r eval/requirements.txt
.venv/Scripts/python.exe eval/harvest_real.py
.venv/Scripts/python.exe eval/defend_real.py
```

Harvesting took about four and a half minutes here. The full tables, including
a copy trained on labels alone, are in `eval/results/defences_real.md`.

### Does the budget hold against a stronger attacker?

Everything above uses TF-IDF plus logistic regression as the attacker's
student, which is about as weak an attacker as exists. A real attacker
fine-tunes a pretrained language model instead. So the same harvested pairs
were replayed once more, this time training `distilbert-base-uncased` (the
public pretrained weights you'd download from Hugging Face, never the
victim's own weights) rather than TF-IDF, and the two are compared on
identical data.

| Pairs harvested | TF-IDF copy (weak attacker) | DistilBERT copy (real attacker) |
|---|---|---|
| 50 | 55.9% | 65.1% |
| 200 | 62.9% | 81.5% |
| 800 | 69.3% | 85.6% |
| 2,000 | 72.5% | 86.2% |

![Weak attacker versus a real attacker on the same harvested pairs](eval/figures/defence_budget_fidelity_strong.png)

This changes the conclusion above, and not in the detector's favour. A budget
of 50 per key does not hold a capable attacker barely above guessing. It
holds them to 65.1%, and four keys worth of pairs (200 total) already gets
them to 81.5%, close to the ceiling this attacker ever reaches with the pairs
available here. A weak attacker needed all 2,000 pairs to get anywhere near
that.

So the honest version of the budget defence: it slows a weak attacker a lot
and a capable one only a little. A budget still has some value, since every
attacker needs some minimum number of pairs no matter how good their student
is, but the number that actually matters is much smaller than the weak-
attacker result suggested, and a business relying on this defence should
size it against a real attacker, not a toy one.

One caveat in the other direction: training `distilbert-base-uncased` on 2,000
pairs took about 19 minutes on this machine's CPU here, against seconds for the
TF-IDF model. That cost is not nothing, but it is a one-time cost for the
attacker, not a per-query one, so it does not change the numbers above; it
just means a serious attacker needs a GPU, not that they need one to succeed.

And these real-text copies still agree with the victim less than the copies in
the synthetic experiment further down (86.2% here at best against 98.7%
there), which is one more sign the synthetic numbers were flattering, even
against a much stronger attacker than that experiment used.

Run it yourself (the API does not need to be running, since it replays the
pairs `eval/harvest_real.py` already collected):

```bash
.venv/Scripts/python.exe eval/defend_real_strong.py
```

Putting the whole project together:

| Attacker | What stops it |
|---|---|
| Probes the model's decision boundary | the detector: 3 of 3 caught, 0 false alarms on real customers |
| Harvests ordinary text with one key, weak student | a per-key query budget: holds them near guessing |
| Harvests ordinary text with one key, capable student | a per-key query budget: slows them, does not stop them |
| Harvests ordinary text with many cheap keys | nothing in this repo; it needs keys tied to real identities |

## Which signals matter, and does it depend on the victim model?

Two questions that could have quietly undermined everything above. Is the
detector only working because this particular model is very sure of itself? And
which of the ten signals is actually doing the catching?

**Which signals.** Each signal was removed in turn and the same clients were
rescored, with the baseline, the cutoff and the two-signal rule left exactly as
they were.

| Signals used | Real text: attackers caught | Synthetic: attackers caught |
|---|---|---|
| all ten | 3 of 10 | 10 of 10 |
| without `near_dup_rate` | 1 of 10 | 8 of 10 |
| without `herdan_c` | 1 of 10 | 8 of 10 |
| without the two confidence signals | 3 of 10 | 10 of 10 |
| the six signals that only read the query text | 3 of 10 | 10 of 10 |
| timing and label balance alone | 0 of 10 | 0 of 10 |
| the two confidence signals alone | 0 of 10 | 1 of 10 |

`near_dup_rate` and `herdan_c` do the work. The confidence signals do not. On
the synthetic set, removing them also removed the one false alarm and lost no
attackers, so there they were a net negative. Earlier versions of this README
said the confidence signal was carrying the detector. That was wrong. It looked
that way because its deviations were enormous (z-scores in the dozens), but a
big deviation is not the same as being needed when other signals already supply
the two flags.

**A different victim.** The whole real-text experiment was rerun against
`cardiffnlp/twitter-roberta-base-sentiment-latest`, a different architecture
trained on different data, with three labels instead of two.

| | DistilBERT SST-2 | RoBERTa (tweets) |
|---|---|---|
| Median confidence on real customer text | 0.998 | 0.839 |
| Answers at 99% confidence or higher | 73.0% | 0.0% |
| Answers below 90% confidence | 6.7% | 65.3% |
| Learned baseline for 10th percentile confidence | 0.938 | 0.511 |
| Attackers caught | 3 of 10 | 3 of 10 |
| Customers wrongly flagged | 0 of 10 | 0 of 10 |
| Attackers caught without the confidence signals | 3 of 10 | 3 of 10 |

The two models behave very differently. RoBERTa is far less sure of itself, and
the learned baseline moved to match. The detection result did not change at all,
and the same three attackers were caught either way. The one place the models
differed: `low_conf_rate` fired on three RoBERTa customers, each time alone, so
none was flagged. A less certain model makes the confidence signals noisier for
honest users, which is one more reason not to lean on them.

Run it yourself:

```bash
.venv/Scripts/python.exe eval/ablate_signals.py --log data/logs/real_eval.jsonl \
  --thresholds data/logs/real_thresholds.json --attack-prefix atk- --tag real_distilbert
```

The second-model run starts the API with `MODEL_NAME=cardiffnlp/twitter-roberta-base-sentiment-latest`
and uses `eval/run_real_experiment.py --tag roberta`. It downloads about 500 MB.

## Red-teaming the detector

Every attacker so far was static. A real one gets caught, works out why, and
tries again. `eval/adaptive_attacker.py` plays that game with a boundary prober,
the kind the detector reliably catches. Each round it sends 60 real queries to the
live API under a fresh key and gets scored by the real detector against the
real-customer baseline. If it is flagged it changes tactics and goes again.
Success is three unflagged rounds in a row with the same tactics.

Three attackers, three trials each:

| Attacker | Fully evaded | First unflagged round |
|---|---|---|
| **Informed:** sees which signals fired and reacts to each | 3 of 3 | round 3 |
| **Blind:** sees only "flagged or not", changes one tactic at random | 0 of 3 | none in 12 rounds |
| **Prior knowledge:** no feedback, starts with the standard countermeasures | 3 of 3 | **round 1** |

![Signals fired and boundary information gained, per round, for the three attackers](eval/figures/adaptive_attacker.png)

The informed attacker was caught twice, then switched to more seeds, more edits
per probe, no repeated queries, a much bigger substitution vocabulary and
human-looking timing. That was enough. The blind attacker failed, but only
because it picks tactics at random. The third attacker shows what that means: one
that never sees any feedback and simply uses those same countermeasures from the
start was **never flagged in any round of any trial**. At most one signal fired,
and it takes two.

So keeping the detector's reasons secret does not decide anything. The ten
signals are described in this README, and an attacker who reads it knows what to
avoid. Evasion also did not cost the attacker anything by the measure used here.
Label flips (edited queries whose answer differs from their own seed's, which is
real information about the decision boundary) averaged 0.3 per round for the
naive attacker and 2 to 3 for the evaders, because more edits per probe finds
more flips.

One real bug came out of this. The API's 429 response used to include the list of
signals that got a key blocked, which is exactly the feedback the informed
attacker needed. It stayed in `blocked.json` for the operator but should never
have been sent to the client. It now returns a generic message, and a test checks
that no reason leaks. That would have saved an attacker about two rounds, not
changed the outcome.

Honest limits: this is one type of attacker, three trials each, and the flip
counts are small and noisy (0 to 6 per round). The attacker rotates to a fresh
key every round. Timing evasion is easy here partly because the benign timing
comes from our own generator. I have not tried any fixes. Ideas worth testing
are keeping cutoffs secret or varying them per key, and signals that are costly
to imitate, such as how much of the input space all customers together cover.

```bash
.venv/Scripts/python.exe eval/adaptive_attacker.py --trials 3 --max-rounds 12
```

Needs the DistilBERT API running. It takes a few minutes.

## How fast is it?

`eval/bench_throughput.py` measures the detector and the API separately, because
they have different limits. Measured on a 12-thread Windows laptop.

**The detector** parses a log, groups it by key, builds 30-request windows,
computes the ten signals and applies the rule. No API or model involved.

| Requests in log | Total time | Throughput |
|---|---|---|
| 10,000 | 0.32 s | 31,600 requests/s |
| 100,000 | 4.9 s | 20,400 requests/s |
| 500,000 | 21.6 s | 23,200 requests/s |

Computing all ten signals for one window takes under a millisecond. That is more
than a thousand times faster than the model it protects can answer (DistilBERT
takes a median of 76 ms per request here, about 13 requests a second, and
RoBERTa 332 ms, about 3 a second), so detection is never the bottleneck.

**A bug this found.** `--watch` used to re-read and rescore the entire log every
few seconds. That is fine at first and quietly stops working: a 100,000-request
log took 3 to 5 seconds per cycle, at or above the default 3 second interval, and
500,000 took over 20. It now remembers where it stopped reading, parses only new
lines, and rescores only the clients that sent them. A cycle on a 100,000-request
log went from 3.15 s to 42 ms, about 76 times faster. A replay of real logged
clients through the new watcher blocked exactly the same two attackers as the
one-shot scorer, and nine tests cover partial lines, Windows line endings,
rotated files and late-arriving rows. The catch is that it keeps every row in
memory, so a very long watch uses memory in proportion to the log.

**The API**, with the stub model so inference is excluded:

| Log durability | Requests/s | p50 latency |
|---|---|---|
| fsync every line (default) | 357 to 596 | 14 to 25 ms |
| no fsync (`LOG_FSYNC=0`) | 465 to 749 | 9 to 17 ms |

The ranges are two separate runs on the same machine, which differed by about
1.7 times, so treat these as a rough range and not a precise figure. Both times
the fsync cost about a fifth of throughput. The default keeps it, because losing
audit lines when the process crashes is worse than being a bit slower.

```bash
.venv/Scripts/python.exe eval/bench_throughput.py
```

## Results on synthetic traffic

These are the earlier numbers, from template-generated customers and attackers.
Read them next to the real-text results above: synthetic attackers turned out
to be far easier to separate than real ones.

1,200 requests from 25 clients: 15 normal customers and 10 attacker keys. The
baseline was learned from 8 completely separate normal clients with deliberately
mixed behaviour: slow and fast, bursty and steady, a couple paced like a
machine.

```
                 predicted
               attack  benign
actual attack      10       0
actual benign       1      14

precision 0.909   recall 1.000   f1 0.952
```

Caught 10 out of 10 attackers. One false alarm out of 15 normal customers.

![Signals fired per client](eval/figures/flags_per_client.png)

Every red bar past the dashed line is an attacker caught. The one green bar past
it is the false alarm. Regenerate the chart with
`python eval/plot.py --log <log> --thresholds thresholds.json` (needs
`pip install -r eval/requirements.txt`).

**About that false alarm.** It was `cust-service-heavy`: 90 requests, steady
machine pacing, no jitter. It tripped on confidence. Two of its queries in one
window came out at confidence 0.55, and it turned out our own benign generator
had built sentences like *"the movie left me cold I'd recommend it."* which the
model, reasonably, couldn't make its mind up about. So part of that false alarm
is our fake customers being a bit weird. But part of it is real: a client with
90 requests gets judged on 5 windows, and the worst one counts. More windows,
more chances to trip. Heavy legitimate users are the ones most at risk of a
false alarm, and that's worth knowing before you deploy.

### Evasion ladder

Each row below adds one more trick on top of the last. Everything from L1 down
runs at about one request per second. No rate limit anywhere would notice them.

| | What the attacker did | Speed | Caught? | What gave it away |
|---|---|---|---|---|
| **L0** | nothing, just went fast | 20/s | yes (3 signals) | vocabulary, near-duplicates, burstiness |
| **L1** | slowed to human speed | 1/s | yes (4 signals) | vocabulary, burstiness, near-duplicates |
| **L2** | added random delays | 1/s | yes (6 signals) | confidence, vocabulary, near-duplicates |
| **L3** | spaced requests like a real person | 1/s | yes (3 signals) | vocabulary, near-duplicates, word choice |
| **L4** | split across 5 API keys | 0.24/s each | **all 5 caught** (2 to 3 signals each) | vocabulary, near-duplicates, confidence |
| **L5** | used natural-sounding sentences | 1/s | yes (3 signals) | confidence, near-duplicates, vocabulary |

L4 is the one worth pointing at. Five keys, a quarter of a request per second
each. That beats any rate limit you'd realistically configure. All five were
still caught individually, because the detector is looking at the shape of the
queries, not the count.

Two of the five L4 keys sit at exactly 2 signals, which is the minimum. That's
thinner than we'd like. Making the baseline broader (more varied normal
customers) cut the false alarms but also shrank the margin on the hardest
attackers. That trade-off is real and you don't get to escape it.

### Does blocking actually protect the model?

Detection is only worth something if it stops the theft, so we measured that
directly by playing the attacker. `eval/steal.py` sends natural-looking queries
to the victim, keeps the question and answer pairs, trains a small copy on them
(a plain naive Bayes classifier, written in the script), and then measures how
often the copy agrees with the victim on 300 sentences neither of them trained
on.

It does this twice. Once with nobody watching, and once with the detector
enforcing in the loop, so the attacker gets 429s the moment it's flagged.
Nothing is simulated: it's the same detector, the same blocklist file, the
same API.

```
harvested pairs          fidelity
----------------------------------
10                          53.3%
20                          71.7%
30                          87.3%  <- where enforcement cut the attacker off
50                          91.0%
100                         93.3%
200                         94.7%
300                         95.3%
500                         98.7%

copy trained WITHOUT enforcement :  500 pairs -> 98.7% agreement with the victim
copy trained WITH enforcement    :   30 pairs -> 87.3% agreement with the victim
always guess the majority label  :         -> 53.3%
```

![Stolen copy fidelity against harvest size](eval/figures/stolen_model_fidelity.png)

The attacker was cut off after 30 queries, which is the earliest the detector
can act at all (it won't judge anyone on fewer than 30). Left alone, the same
attacker got 500 pairs and a copy that disagrees with the victim about one time
in eighty. Blocked, it was left with a copy that's wrong about one time in
eight. That's a tenfold difference in error rate, and it's the difference the
detector makes in the attacker's own currency.

Two honest caveats. The held-out sentences come from the same template family
as the attacker's queries, so the copy looks better here than it would on real
text; 87% after 30 pairs is flattering to the attacker. And a naive Bayes over
a 60-word vocabulary is a weak student on purpose. The absolute numbers aren't
the point. The gap is.

Run it yourself with the API up and a baseline calibrated:

```bash
.venv/Scripts/python.exe eval/steal.py
```

## What's not great about this

Being honest, because most of this isn't fixed.

**Passive harvesting of real text isn't detected.** On real data, 0 of 7 harvester keys were caught (see Results on real text). The detector is good at spotting someone probing the model and bad at spotting someone who just sends a lot of ordinary-looking text. That's the biggest limit of the whole approach. A per-key query budget helps a lot against a weak attacker and only a little against a capable one, and one with many cheap keys still gets most of the model either way (see Defending against harvesting).

**The synthetic customers are still fake.** It's more varied than it was (15
clients, different speeds, some bursty, some steady, some machine-paced), but it
all comes from one template generator. Real users are messier in ways this
can't show. Treat 1 false alarm in 15 as a rough indication, not a rate you can
quote.

**Heavy users are the false-alarm risk.** Judging on the worst window is the
right call against attackers who pad their traffic, but it means a client with
lots of windows gets more rolls of the dice. A fairer rule for high-volume
clients is an open question.

**Two signals do the work, and they are easy to imitate.** `near_dup_rate` and
`herdan_c` are what catch anyone: removing either loses attackers on both
victim models. An attacker who spreads its probes over more seeds and draws
from a bigger vocabulary stops triggering them (see Red-teaming the detector).
Earlier versions of this README blamed the detector's fragility on the
confidence signal, which turned out to be wrong. The burstiness signal leans
on benign clients being bursty, which is as much a property of our generator
as of real people, and it drifts if the calibration clients ran at a different
pace from the ones being judged.

**An attacker who knows the signals gets past it.** The ten signals are
described in this README. A boundary prober using the obvious countermeasures
was never flagged, with no feedback needed, and it still learned about the
boundary. I haven't tested any fix.

**Automated doesn't mean malicious.** The false alarm above was a service
account. In earlier testing, calibrating a separate baseline for service
accounts fixed exactly this kind of case, with attack recall unchanged. Adding a
few machine-paced clients to a human baseline (which is what we did this round)
helps some but not fully, because a handful of clients can't move a median far.
If you deploy this, calibrate per class of client.

**Grouping keys is rough.** `campaign.py` merged several different attackers
into one group because they came from the same tooling. It really answers "same
tooling?" rather than "same person?". And an attacker who splits the work so
that their keys *don't* overlap slips past it entirely, since it's looking for
similarity.

**Everything is small.** 30 requests per window, 1 to 5 windows per client, 19
windows to calibrate from. Percentages worked out from 30 samples bounce around
a lot.

**We only tested the attacks we thought of.** Calibrating on normal traffic
only limits the damage, since the detector never sees our attacks while
learning, but it doesn't remove it. The real-text attackers are ours too, and
the red-team run shows an attacker who knows the signals beats them. Only one
kind of adaptive attacker has been tried, three times each.

**Live watching keeps every row in memory.** The incremental reader remembers
each client's whole history so the worst window still counts. That is fine for
the scale tested and grows with the log for a very long run.

**The synthetic stolen-copy numbers are optimistic for the attacker.** The held-out set
is built from the same templates the attacker queries with, and the student is
deliberately tiny. On real text, 30 pairs would buy the attacker much less than
87%. The tenfold gap in error rate is the honest takeaway; the absolute
percentages are not.

**Blocking is blunt.** Once flagged, a key gets 429 on everything until the
blocklist is cleared. There's no appeal, no cooldown, no partial throttle. Fine
for a demo, not something you'd ship as-is.
