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

And it doesn't stop at noticing. Once a key is flagged, the API starts
answering it with HTTP 429 and the attacker's harvest stops.

**Who'd use this:** a team running a paid inference API. Sentiment,
moderation, classification, anything sold per call.

**What it costs to get wrong:** if you wrongly flag a real customer, they get
throttled or cut off, and that's a support ticket and maybe a lost account. So
the detector never just says "attacker". It prints which signals fired, how far
off normal they were, and a plain-English reason for each one. And it won't
flag anyone on a single signal alone.

## What's in here

```
api/        the "victim" API - a sentiment model that logs every request
traffic/    fake traffic: normal customers and several kinds of attacker
detector/   detection - features, calibration, scoring, enforcement, dashboard
eval/       measuring the detector, plus the chart in eval/figures/
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

`--watch` re-reads the log every few seconds and alerts as traffic arrives:

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

## Results

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

## What's not great about this

Being honest, because most of this isn't fixed.

**The "normal" traffic is still fake.** It's more varied than it was (15
clients, different speeds, some bursty, some steady, some machine-paced), but it
all comes from one template generator. Real users are messier in ways this
can't show. Treat 1 false alarm in 15 as a rough indication, not a rate you can
quote.

**Heavy users are the false-alarm risk.** Judging on the worst window is the
right call against attackers who pad their traffic, but it means a client with
lots of windows gets more rolls of the dice. A fairer rule for high-volume
clients is an open question.

**Two signals do a lot of the work, and both are shaky.** The confidence signal
works well because this particular model is very sure of itself on ordinary
text (over 0.99 almost always), which makes probing queries stand out. A
better-calibrated model would blunt it. The burstiness signal leans on benign
clients being bursty, which is as much a property of our generator as of real
people, and it drifts if the calibration clients ran at a different pace from
the ones being judged.

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
learning, but it doesn't remove it. An attacker pulling real sentences from a
real corpus at human speed hasn't been tried, and the margins on our closest
cases were thin enough that it might get through.

**Blocking is blunt.** Once flagged, a key gets 429 on everything until the
blocklist is cleared. There's no appeal, no cooldown, no partial throttle. Fine
for a demo, not something you'd ship as-is.

## Team

Adwait M. (https://github.com/adwaitm0106)
