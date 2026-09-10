# Project

**Detecting model-extraction attacks from API request logs.**

A model-extraction attack steals a machine learning model by querying it: the
attacker sends inputs, records the outputs, and trains a copy on the resulting
pairs. No breach is required — the attack uses the API exactly as intended,
one legitimate request at a time.

This repository is a complete, runnable testbed for detecting that:

| Component | What it is |
|---|---|
| `api/` | A **victim** sentiment API (DistilBERT SST-2) that logs every query |
| `traffic/` | A generator producing labelled **benign and attacker** traffic |
| `detector/` | Feature extraction, benign-only calibration, and scoring |
| `eval/` | Confusion matrix over labelled logs |
| `data/logs/` | Where request logs land (git-ignored) |

The detector deliberately **cannot see query volume**. Rate is the obvious
extraction signal and the cheapest to evade — an attacker who throttles to
human pace defeats it at no cost but time. Every feature here is
rate-independent, so detection has to come from the *shape* of the queries.

## Quickstart

Nothing is required on the host except Docker Desktop (or Docker Engine with
the Compose plugin). Python, torch and the model weights all live inside the
image.

```bash
git clone https://github.com/adwaitm0106/extraction-detector.git
cd extraction-detector
docker compose up --build
```

> **Not yet verified.** The Docker setup has never been built or run — Docker
> was unavailable on the development machine. The compose file is valid YAML
> and the Dockerfile is written carefully, but expect it to need a debugging
> pass on first use. The non-Docker path below *has* been verified end to end
> from a clean clone.

The first build downloads CPU-only torch wheels and bakes the
`distilbert-base-uncased-finetuned-sst-2-english` weights into the image, so it
takes several minutes. Later builds are cached.

The API is ready once `/health` reports `model_loaded: true`:

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","model_loaded":true}
```

Send a prediction. `X-API-Key` is required and identifies the caller in the
logs; any non-empty string works:

```bash
curl -s -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: demo-key-1" \
  -d '{"input":"This movie was absolutely fantastic."}'
# {"label":"POSITIVE","confidence":0.9998722076416016}
```

Every successful request appends one JSON line to `data/logs/requests.jsonl`
on the host, so the detector can tail it live. Stop with `docker compose down`.

**On Windows PowerShell**, `curl` is an alias for `Invoke-WebRequest` and will
reject the flags above. Use `curl.exe`, or the native form:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict -Method Post `
  -Headers @{"X-API-Key"="demo-key-1"} -ContentType "application/json" `
  -Body '{"input":"This movie was absolutely fantastic."}'
```

### Without Docker

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r api/requirements.txt      # Windows
.venv/Scripts/python.exe -m uvicorn api.main:app --port 8000
```

Verify everything works in one command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
```

## Architecture

```
   traffic/generate.py                 api/main.py
   ┌──────────────────┐   HTTP    ┌──────────────────┐
   │ benign clients   │──────────▶│  DistilBERT      │
   │ attacker clients │  /predict │  SST-2, CPU      │
   └──────────────────┘           └────────┬─────────┘
                                           │ one JSON line per request
                                           ▼
                                data/logs/requests.jsonl
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
        detector/calibrate.py     detector/score.py      detector/dashboard.py
          benign traffic only      z vs baseline           live web view
                    │                      ▲
                    └──▶ thresholds.json ──┤
                                           │
                                detector/campaign.py
                             cross-key linkage + pooled score
```

**The victim API** loads the model once at startup and holds it in module
state. Inference runs in a threadpool under a lock (HF pipelines are not
thread-safe), so a slow prediction cannot block the event loop. Every
successful request appends one line — `ts`, `api_key`, `input`,
`predicted_label`, `confidence`, `latency_ms` — flushed and `fsync`ed
immediately so another process can tail it. Failed requests (401/422) are
never logged.

**The traffic generator** gives every client its own API key, which is the
ground-truth label. Profiles: `benign` (natural sentences, bursty human
pacing, ~20% repeats), `random` (uniform word salad — broad input coverage),
`boundary` (near-duplicate probes that vary one token to find where the label
flips), `sweep` (deterministic template enumeration), `natural`
(natural-looking sentences enumerated systematically — designed to pass
per-key content checks), and `mixed` (benign clients plus one attacker,
concurrently). Attackers can throttle (`--attacker-rate`), jitter
(`--attacker-jitter`), use memoryless Poisson arrivals
(`--attacker-pacing poisson`), or split the campaign across K API keys
(`--split K`) to evade detection.

**The detector** computes ten rate-independent, sample-size-normalised
features per window of 30 requests:

| Feature | Signal |
|---|---|
| `exact_dup_rate`, `near_dup_rate` | Boundary probing repeats itself; random sampling never does |
| `herdan_c`, `token_entropy_norm` | Generated vocabularies are narrow or unnaturally uniform |
| `len_cv`, `template_share` | Enumeration produces structurally identical queries |
| `low_conf_rate`, `conf_p10` | Probing concentrates near the decision boundary |
| `iat_burstiness` | Humans work in bursts; scripts do not |
| `label_balance` | Sweeps drift toward the model's prior |

**Cross-key correlation** (`detector/campaign.py`) addresses the attacker who
splits a campaign across several API keys. It links pairs of keys that are far
more similar than benign pairs typically are — on shared vocabulary, shared
structural skeletons, cross-key near-duplicates, and overlapping activity
windows — then pools each connected component and scores the union. **Both**
stages must agree before anything is called a campaign: linkage alone would
flag two colleagues at the same company, and pooled anomaly alone is more
likely several unrelated oddities than one actor.

**Calibration** fits a robust baseline — median and MAD — on **benign traffic
only**. Scoring is a two-sided robust z-score per feature; a client is called
ATTACK when at least two features deviate by 3.5σ or more. The worst window
wins, so an attacker cannot dilute a probing burst by padding it with
innocuous queries.

## Running the demo

Start the API, then in another terminal:

```bash
# 1. Benign traffic to calibrate against (attack traffic must NOT appear here)
python traffic/generate.py --profile benign --n 60 --rate 1.2 --jitter 0.5 \
  --api-key cal-user-0 --seed 100
cp data/logs/requests.jsonl data/logs/benign_calib.jsonl
rm data/logs/requests.jsonl

# 2. Fit the baseline
python detector/calibrate.py --log data/logs/benign_calib.jsonl --out thresholds.json

# 3. Evaluation traffic: benign users plus a throttled attacker
python traffic/generate.py --profile benign   --n 60 --rate 1.2 --jitter 0.5 \
  --api-key eval-user-0 --seed 200
python traffic/generate.py --profile boundary --n 60 --rate 1.0 \
  --attacker-pacing poisson --api-key atk-boundary --seed 301

# 4. Score, and measure
python detector/score.py    --log data/logs/requests.jsonl
python eval/evaluate.py     --log data/logs/requests.jsonl --attack-prefix atk-

# 5. Look for campaigns split across multiple keys
python traffic/generate.py --profile natural --n 150 --split 5   --attacker-rate 1.5 --attacker-pacing poisson --attacker-key ghost --seed 900
python detector/campaign.py --log data/logs/requests.jsonl
```

### Dashboard

```bash
python -m uvicorn detector.dashboard:app --port 8050
```

Open <http://127.0.0.1:8050>. It re-scores every client every three seconds
and shows the flag count, the verdict, and **which features fired with what
deviation** — a verdict without a reason is not much use to an operator
deciding whether to revoke a key. It is read-only and safe to run against a
live experiment.

### Tests

```bash
python api/test_api.py                 # 36 hostile-input cases against a running API
powershell -File scripts\smoke_test.ps1 # 12 end-to-end checks, starts its own server
```

## Results

Six attackers, four benign clients, evaluated against a baseline calibrated on
separate benign traffic with **non-overlapping seeds**. Every attacker was
throttled to roughly 1 req/s — indistinguishable from a human on volume — and
three used Poisson inter-arrivals.

```
                 predicted
               attack  benign
actual attack       6       0
actual benign       0       4

precision 1.000   recall 1.000   f1 1.000
```

**These numbers should not be trusted as a measure of real-world performance,
and the section below explains why.** Ten synthetic clients from a single
generator is a demonstration that the approach separates these profiles, not
evidence of a deployable detector.

### Cross-key campaigns

A campaign of 150 queries was split five ways — 30 queries per key at roughly
0.24 req/s each — and run against the same baseline.

| Campaign | Per-key verdict | Linked as one group | Pooled |
|---|---|---|---|
| `ghost-*` (template sweep) | 5/5 ATTACK | yes | CAMPAIGN |
| `stealth-*` (natural text, systematic) | 5/5 ATTACK | yes | CAMPAIGN |
| `wraith-*` (natural text, hardened) | 5/5 ATTACK | **no** | — |

No benign client was ever pulled into a group.

**This corrected an assumption.** Splitting a campaign across keys was expected
to be the cheapest evasion available. It is not — at least not against this
detector, because the features are per-window *shape* measures that do not
depend on volume. A key sending 30 systematic queries looks as anomalous as one
sending 3000. Distribution defeats rate-based detection, which this detector
deliberately does not use.

Cross-key linkage still earns its place, for **attribution**: it reports that
ten flagged keys are two actors rather than ten independent ones, which is what
an operator needs in order to respond. But on this evidence it is a second
layer, not the primary defence.

### Defects found and fixed during evaluation

- **Degenerate feature scale, twice.** `low_conf_rate` and later
  `label_balance` are zero (or near-constant) across benign calibration
  windows, so their MAD collapsed and an arbitrary `1e-3` floor turned a
  single unusual request into a 33σ event — one false positive carried
  z-scores up to 266. Fixed by deriving the floor from window size: a
  proportion over W requests moves in steps of 1/W, so deviations below one
  step are quantisation noise. The second instance was only noticed because an
  attack was being caught for the *wrong reason* — every member of a campaign
  showed an identical z of 18.2.
- **A 500 on legal input.** A 2000-character request can exceed DistilBERT's
  512-token window (`"a " * 1000` is 2000 chars but 1002 tokens), raising a
  tensor size mismatch. Fixed by truncating at the pipeline call.
- **Sentiment-skewed enumeration.** The first `natural` attack profile
  advanced its opinion index once per pass over subjects, so any short slice
  was 100% one sentiment — trivially detectable for a reason that had nothing
  to do with extraction. Fixed with coprime strides, which made the attacker
  meaningfully harder and the evaluation honest.

## Shortcomings

Stated plainly, because most of these are unresolved.

**The benign class is synthetic and far too homogeneous.** All benign traffic
comes from one template-based generator. Real user traffic is messier in ways
that would produce false positives this testbed cannot show. The false-positive
rate reported above is close to meaningless; treat it as a lower bound on a
number that is genuinely unknown.

**`conf_p10` is doing much of the work, and it is model-specific.** DistilBERT
SST-2 is extremely confident on ordinary text (>0.99 routinely), which makes
low-confidence queries stand out sharply. A better-calibrated victim model
would weaken this feature substantially, and by how much has not been measured.

**Automated is not the same as attacking.** A legitimate machine-paced
integration sending perfectly ordinary sentences was flagged as an attacker.
Adding a few service accounts to the human baseline does *not* fix this — a
minority cannot move a median. Calibrating a **separate baseline per client
class** does: measured here, the same legitimate client scored 2 flags
(ATTACK) against a human baseline and 0 flags (benign) against a service-account
baseline, with attack recall unchanged at 6/6. This is an operational
requirement, not an optional refinement.

**The attacks are the ones we thought of.** Four profiles, all written by the
same person who wrote the detector. Benign-only calibration limits how much
this can bias results — the detector never sees an attack sample and cannot
learn their signatures — but it does not eliminate it. An attacker who
generates queries from real review text at human pace with natural vocabulary
would defeat most of these features, and has not been tested.

**Cross-key linkage is evadable, and over-merges.** The hardened `wraith`
campaign was not linked at all: partitioning a grid with coprime strides makes
members' queries *complementary* rather than overlapping, which is precisely
what similarity-based linkage looks for. In the other direction, two separate
campaigns using the same tooling were merged into a single group of ten by
transitive closure. Linkage answers "same tooling?", not "same actor?", and the
report should be read that way.

**Detection margins on the hardest attacker are thin.** `wraith` was caught,
but at 2–4 flags with z-scores of 3.5–5.5, against a 3.5 cutoff. The earlier,
cruder profiles cleared it by z-scores of 15–50. An attacker drawing from a
genuinely varied corpus rather than a template grid would likely fall below the
threshold, and that has not been tested.

**No adaptive attacker.** Everything here is static. An attacker with
dashboard feedback could tune queries until they stopped being flagged. The
features were chosen to make that expensive rather than impossible.

**Small samples.** 30-request windows, 3 windows per client, 33 calibration
windows. Ratios estimated from 30 samples are noisy, and the baseline's spread
estimates are correspondingly rough.

**Docker is unverified.** See the note in Quickstart.

## Team

Adwait M. — <https://github.com/adwaitm0106>
