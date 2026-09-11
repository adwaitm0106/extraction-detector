# Extraction Detector

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

**Who'd use this:** a team running a paid inference API. Sentiment,
moderation, classification, anything sold per call.

**What it costs to get wrong:** if you wrongly flag a real customer, they get
throttled or cut off, and that's a support ticket and maybe a lost account. So
the detector never just says "attacker". It shows which signals fired and how
far off normal they were, and it won't flag anyone on a single signal alone.

## What's in here

```
api/        the "victim" API - a sentiment model that logs every request
traffic/    fake traffic: normal customers and several kinds of attacker
detector/   the actual detection - features, calibration, scoring, dashboard
eval/       scoring the detector: how many caught, how many false alarms
demo/       one script that runs the whole story end to end
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
like, sends benign traffic, then sends an attacker, and alerts on it live:

```powershell
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```

Takes about 2 and a half minutes the first time. There's a `demo/run_demo.sh`
for Mac and Linux. It cleans up after itself, including if you hit Ctrl+C.

**What you should see:**

1. `API ready: model_loaded=true` means the model has loaded
2. A calibration phase with four fake customers. This is the detector learning
   what normal traffic looks like
3. **PHASE 1** in green: normal customers querying. You should see
   `30 requests scored - all clean` and **no alerts**
4. **PHASE 2** in red: the attacker starts. About 25 seconds later a red
   `[ALERT] EXTRACTION SUSPECTED` line appears with the signals that fired
5. A results table, then everything shuts down

If Phase 1 stays quiet and Phase 2 alerts, it's working.

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
.venv/Scripts/python.exe detector/calibrate.py \
  --log data/logs/benign_calib.jsonl --out thresholds.json

# 3. Now traffic to actually test on - a customer and an attacker
.venv/Scripts/python.exe traffic/generate.py --profile benign --n 45 \
  --rate 3 --jitter 0.5 --api-key customer-0 --seed 200
.venv/Scripts/python.exe traffic/generate.py --profile boundary --n 45 \
  --rate 1.0 --attacker-pacing poisson --api-key L3-poisson --seed 303

# 4. Score it
.venv/Scripts/python.exe detector/score.py --log data/logs/requests.jsonl
.venv/Scripts/python.exe eval/evaluate.py --log data/logs/requests.jsonl \
  --attack-prefix L0- L1- L2- L3- L4- L5-
```

**Don't reduce the number of clients in step 1.** The detector works on windows
of 30 requests and needs at least 5 windows to learn anything. Four clients at
45 requests each gives 8. One client at 45 gives 2, and calibration will refuse
to run.

### Watching it live

`score.py --watch` re-reads the log every few seconds and alerts as traffic
arrives:

```bash
.venv/Scripts/python.exe detector/score.py --log data/logs/requests.jsonl --watch
```

Alerts look like this:

```
[ALERT 19:12:04] EXTRACTION SUSPECTED  api_key=L3-poisson  flags=5/10  requests=45
  signals: near_dup_rate(7.0), herdan_c(5.3), len_cv(4.5), token_entropy_norm(3.7)
```

There's a web dashboard too:

```bash
.venv/Scripts/python.exe -m uvicorn detector.dashboard:app --port 8050
```

Then open <http://127.0.0.1:8050>. It shows every client, whether it's flagged,
and which signals fired. It only reads the log, so it's safe to leave running
during an experiment.

### Docker

There's a `Dockerfile` and a `docker-compose.yml`, but **they have never been
run**. Docker wasn't installed on the machine this was built on. The files look
right, but nobody has proved it. Use the venv instructions above for anything
that matters.

```bash
docker compose up --build
```

## Things that will trip you up

- **Wrong folder.** Every path is relative to `extraction-detector/`. From
  anywhere else you get errors that never mention directories.
- **`curl` in PowerShell isn't curl.** Use `curl.exe`.
- **The API writes the log, not the traffic generator.** To put the log
  somewhere else, set `LOG_PATH` on the *server* before starting it. Setting it
  on the generator does nothing, it's silently ignored.
- **Nothing works until you calibrate.** `score.py` needs `thresholds.json`,
  which `calibrate.py` creates. Run it on normal traffic only.
- **A client needs 30 requests before it can be judged.** Below that it shows
  as `insufficient`. Live, that's about 20 seconds before the first verdict.
- **`--api-key` is ignored with `--split` or `--profile mixed`.** Those modes
  name their own keys, based on `--attacker-key`.
- **Calibrate at the same pace you'll judge.** The burstiness signal shifts
  with how fast the calibration clients ran. We learned this the hard way: the
  demo used to calibrate at 6 requests a second and then judge customers at
  1.5, and those customers came out at z=11 on burstiness. Same rate on both
  sides and they dropped to zero.

## How it works

```
traffic/generate.py  ──HTTP──▶  api/main.py  ──▶  data/logs/requests.jsonl
 normal + attacker               DistilBERT              one line per request
                                                                 │
                       ┌─────────────────────────────────────────┤
                       ▼                    ▼                    ▼
              detector/calibrate.py   detector/score.py   detector/dashboard.py
              learns from normal      flags + alerts      live web view
                       │                    ▲
                       └─ thresholds.json ──┘
```

**The API** is a sentiment classifier (DistilBERT fine-tuned on SST-2). It
loads once at startup and writes one JSON line per successful request: time,
API key, the input, the predicted label, the confidence, and how long inference
took. Failed requests aren't logged.

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
out, and the client gets flagged.

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

## Results

555 requests, 14 clients, tested against a baseline built from 4 completely
separate normal clients.

```
                 predicted
               attack  benign
actual attack      10       0
actual benign       0       4

precision 1.000   recall 1.000   f1 1.000
```

Caught 10 out of 10 attackers. Zero false alarms on 4 normal clients.

The interesting part is *which* attackers. Each row below adds one more trick
on top of the last. Everything from L1 down runs at about one request per
second. No rate limit anywhere would notice them.

| | What the attacker did | Speed | Caught? | What gave it away |
|---|---|---|---|---|
| **L0** | nothing, just went fast | 20/s | yes (4 signals) | burstiness, near-duplicates, vocabulary |
| **L1** | slowed to human speed | 1/s | yes (3 signals) | burstiness, near-duplicates, vocabulary |
| **L2** | added random delays | 1/s | yes (7 signals) | confidence, burstiness, near-duplicates |
| **L3** | spaced requests like a real person | 1/s | yes (5 signals) | near-duplicates, vocabulary, length variation |
| **L4** | split across 5 API keys | 0.24/s each | **all 5 caught** | near-duplicates, vocabulary, confidence |
| **L5** | used natural-sounding sentences | 1/s | yes (4 signals) | confidence, burstiness, near-duplicates |

Normal customers over the same run: three tripped nothing at all, one tripped a
single signal, which isn't enough to be flagged.

L4 is the one worth pointing at. Five keys, a quarter of a request per second
each. That beats any rate limit you'd realistically configure. All five were
still caught individually, because the detector is looking at the shape of the
queries, not the count.

## What's not great about this

Being honest, because most of this isn't fixed.

**The "normal" traffic is fake and all looks the same.** Every benign client
comes from one generator using templates. Real users are messier in ways this
setup can't show. So the zero false alarms above isn't a real-world number.
It's the best case, and the true rate is unknown. Four fake clients is not a
sample size.

**Two signals do a lot of the work, and both are shaky.** The confidence signal
works well because this particular model is very sure of itself on ordinary
text (over 0.99 almost always), which makes probing queries stand out. A
better-calibrated model would blunt it. The burstiness signal leans on benign
clients being bursty, which is as much a property of our generator as of real
people, and it drifts if the calibration clients ran at a different pace from
the ones being judged.

**Automated doesn't mean malicious.** A legitimate service account (a backend
integration sending perfectly ordinary text on a schedule) got flagged during
testing. The fix is to calibrate a separate baseline for service accounts
instead of lumping them in with humans. Adding a few of them to a human
baseline doesn't help, because a handful of clients can't shift a median. This
is something you'd have to do before deploying, not an optional extra.

**Grouping keys is rough.** It merged several different attackers into one
group because they came from the same tooling. It really answers "same
tooling?" rather than "same person?". And an attacker who splits the work so
that their keys *don't* overlap slips past it entirely, since it's looking for
similarity.

**Everything is small.** 30 requests per window, 1 to 2 windows per client, 8
windows to calibrate from. Percentages worked out from 30 samples bounce around
a lot.

**We only tested the attacks we thought of.** Calibrating on normal traffic
only limits the damage, since the detector never sees our attacks while
learning, but it doesn't remove it. An attacker pulling real sentences from a real corpus
at human speed hasn't been tried, and the margin on our closest case (L5) was
thin enough that it might get through.

**Docker is untested.** Said above, worth repeating.

**`eval/figures/` is empty.** It's there for charts that never got made.

## Team

Adwait M. (https://github.com/adwaitm0106)
