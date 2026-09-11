# Extraction Detector

**Catching model-extraction attacks in API logs — when the attacker is patient
enough to look like a customer.**

## The problem, and who has it

If you sell access to a model, your model is your product, and your API hands
it out one answer at a time. Model extraction is the attack that exploits
this: query the model, record the outputs, and train a copy on the pairs. No
breach, no exploit, no anomaly in your security tooling. The attacker uses the
product exactly as designed and leaves with a working replica of the asset you
spent money to build.

**Who deploys this:** the ML platform or API product team that owns a
customer-facing inference endpoint — a sentiment, moderation, classification,
or scoring API sold per call.

**What it replaces:** per-key rate limits. Rate limiting is what almost
everyone actually has, and it only stops attackers in a hurry. An attacker
willing to spend a week at one query per second — indistinguishable from a
normal customer on volume — walks straight through it. That is not
hypothetical; it is measured below, and it is the reason this detector
**refuses to use query volume as a signal at all**.

**What a false positive costs:** a paying customer gets throttled or has their
key revoked. That is a support ticket, a refund conversation, and possibly a
churned account. This is why the detector reports *which signals fired with
what deviation* rather than a bare verdict, and why the flag rule requires two
independent signals rather than one. A human should be able to look at an
alert and decide in ten seconds whether it is real.

## Why this approach, now

Extraction stopped being academic once high-quality open models made the
"student" side cheap: an attacker no longer needs to match your architecture,
only to harvest enough labelled examples to fine-tune something adequate. A
few tens of thousands of queries against a well-specified task is enough, and
at commodity API prices that costs less than a laptop.

Defences that work by making queries expensive — rate limits, quotas, pricing
— all share the same weakness: they assume the attacker is impatient. The
alternative is to look at *what is being asked*, not *how much*. Extraction
traffic has to cover the input space systematically to be useful for training,
and that systematic coverage leaves statistical traces — in vocabulary, in
structural repetition, in where queries land relative to the decision
boundary — that ordinary usage does not produce. Those traces are what this
detects, and unlike volume they cannot be removed by slowing down.

## Quickstart

Verified end to end on Windows with Python 3.14 from a clean clone. Takes about
five minutes, most of it the model download.

```bash
git clone https://github.com/adwaitm0106/extraction-detector.git
cd extraction-detector
python -m venv .venv
```

Install dependencies (about 250 MB of CPU-only wheels):

```bash
.venv/Scripts/python.exe -m pip install -r api/requirements.txt
```

On macOS or Linux use `.venv/bin/python` in place of `.venv/Scripts/python.exe`
throughout.

Start the API. The first run downloads ~268 MB of model weights:

```bash
.venv/Scripts/python.exe -m uvicorn api.main:app --port 8000
```

In a second terminal, confirm it is up — wait for `model_loaded: true`:

```bash
curl.exe -s http://127.0.0.1:8000/health
# {"status":"ok","model_loaded":true}
```

Send a prediction. `X-API-Key` is required and identifies the caller in the
logs; any non-empty string works:

```bash
curl.exe -s -X POST http://127.0.0.1:8000/predict -H "Content-Type: application/json" -H "X-API-Key: demo-key-1" -d "{\"input\":\"This movie was absolutely fantastic.\"}"
# {"label":"POSITIVE","confidence":0.9998722076416016}
```

> **PowerShell note:** `curl` is an alias for `Invoke-WebRequest` and rejects
> these flags. Use `curl.exe` as shown. In bash, plain `curl` is fine.

Every successful request appends one JSON line to `data/logs/requests.jsonl`.
Verify the whole install in one command:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
# All 12 checks passed.
```

### Optional: Docker

> **Unverified.** This has never been built or run — Docker was unavailable on
> the development machine. The compose file is valid YAML and the Dockerfile is
> written carefully, but expect it to need debugging. **Use the venv path above
> for anything that matters.**

```bash
docker compose up --build
```

## Running the demo

With the API running, in a second terminal:

```bash
# 1. Benign traffic to calibrate against. The detector must NEVER see attack
#    traffic during calibration. Four clients gives 8 windows; the minimum
#    is 5, so do not reduce this below three clients.
for i in 0 1 2 3; do
  .venv/Scripts/python.exe traffic/generate.py --profile benign --n 45 \
    --rate 3 --jitter 0.5 --api-key "cal-user-$i" --seed $((100+i)) &
done; wait
mv data/logs/requests.jsonl data/logs/benign_calib.jsonl

# 2. Fit the baseline
.venv/Scripts/python.exe detector/calibrate.py \
  --log data/logs/benign_calib.jsonl --out thresholds.json

# 3. Evaluation traffic: ordinary customers plus a throttled attacker.
#    Different seeds from calibration, so there is no overlap.
.venv/Scripts/python.exe traffic/generate.py --profile benign --n 45 \
  --rate 3 --jitter 0.5 --api-key customer-0 --seed 200
.venv/Scripts/python.exe traffic/generate.py --profile boundary --n 45 \
  --rate 1.0 --attacker-pacing poisson --api-key L3-poisson --seed 303

# 4. Score, alert, and measure
.venv/Scripts/python.exe detector/score.py --log data/logs/requests.jsonl
.venv/Scripts/python.exe eval/evaluate.py --log data/logs/requests.jsonl \
  --attack-prefix L0- L1- L2- L3- L4- L5-
```

A single benign client with `--n 45` produces only 2 windows and calibration
will refuse to run. Use three or more clients, or `--n 150` on one client.

### Live alerting

`score.py` prints an alert line for every flagged client:

```
[ALERT 19:12:04] EXTRACTION SUSPECTED  api_key=L3-poisson  flags=5/10  requests=45
  signals: near_dup_rate(7.0), herdan_c(5.3), len_cv(4.5), token_entropy_norm(3.7), exact_dup_rate(3.6)
```

`--watch` tails the log and rescores continuously, so alerts fire live as
traffic arrives. Each key is announced once, and again only if its evidence
changes:

```bash
.venv/Scripts/python.exe detector/score.py --log data/logs/requests.jsonl --watch
```

### One-command demo

```powershell
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```

Starts the API, calibrates, runs a quiet benign phase, then an attacker, with
banners and live alerts — built for a screen recording. `demo/run_demo.sh` is
the POSIX equivalent. Everything it starts is stopped on exit, including on
Ctrl+C. Add `-SkipCalibration` to reuse an existing baseline on a second take.

### Dashboard

```bash
.venv/Scripts/python.exe -m uvicorn detector.dashboard:app --port 8050
```

Open <http://127.0.0.1:8050>. Re-scores every three seconds and shows each
client's flag count, verdict, and the individual feature deviations behind it.
Read-only — safe to run against a live experiment.

### Tests

```bash
.venv/Scripts/python.exe api/test_api.py    # 36 hostile-input cases, needs API running
powershell -File scripts\smoke_test.ps1      # 12 end-to-end checks, starts its own server
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
          benign traffic only    z vs baseline + alerts     live web view
                    │                      ▲
                    └──▶ thresholds.json ──┤
                                           │
                                detector/campaign.py
                             cross-key linkage + pooled score
```

**The victim API** loads the model once at startup into module state. Inference
runs in a threadpool under a lock (HF pipelines are not thread-safe), so a slow
prediction cannot block the event loop. Every successful request appends one
line — `ts`, `api_key`, `input`, `predicted_label`, `confidence`,
`latency_ms` — flushed and `fsync`ed immediately so another process can tail
it. Failed requests (401/422) are never logged.

**The traffic generator** gives every client its own API key, which is the
ground-truth label. Profiles: `benign`, `random` (uniform word salad),
`boundary` (near-duplicate probes varying one token to find where the label
flips), `sweep` (template enumeration), `natural` (natural-looking sentences
enumerated systematically), `mixed`. Attackers can throttle
(`--attacker-rate`), jitter (`--attacker-jitter`), use Poisson arrivals
(`--attacker-pacing poisson`), or split across K keys (`--split K`).

**The detector** computes ten rate-independent, sample-size-normalised features
per window of 30 requests:

| Feature | Signal |
|---|---|
| `exact_dup_rate`, `near_dup_rate` | Boundary probing repeats itself; random sampling never does |
| `herdan_c`, `token_entropy_norm` | Generated vocabularies are narrow or unnaturally uniform |
| `len_cv`, `template_share` | Enumeration produces structurally identical queries |
| `low_conf_rate`, `conf_p10` | Probing concentrates near the decision boundary |
| `iat_burstiness` | Humans work in bursts; scripts do not |
| `label_balance` | Systematic coverage produces an unnaturally even label split |

**Cross-key correlation** (`detector/campaign.py`) links keys that are far more
similar than benign pairs typically are — shared vocabulary, shared structural
skeletons, cross-key near-duplicates, overlapping activity — then pools each
group and scores the union. Both linkage *and* pooled anomaly are required
before anything is called a campaign.

### No train/test leakage

Worth stating explicitly, since it is the usual flaw in results like these:

- Calibration uses **benign traffic only**. The detector never sees an attack
  sample while fitting, so it cannot learn the signatures of the specific
  attack profiles this repo ships.
- Calibration clients (`cal-user-*`, seeds 100–103) and evaluation clients
  (`customer-*` seeds 200–203, attackers seeds 300+) are **disjoint**.
- Only two numbers per feature are fitted — a median and a MAD. There is no
  weight vector.
- The decision constants `Z_FLAG = 3.5` and `MIN_FLAGS = 2` are fixed a priori
  (3.5σ ≈ 0.0005 per feature under a normal baseline; two signals because one
  is a quirk), not tuned against results.

## Results

Measured on 555 requests from 14 clients, against a baseline fitted on 8
windows from 4 separate benign clients.

```
                 predicted
               attack  benign
actual attack      10       0
actual benign       0       4

precision 1.000   recall 1.000   f1 1.000
```

**Detection rate 10/10 (100%). False-positive rate 0/4 (0%).**

### Evasion ladder

Each level adds one evasion technique on top of the previous. All levels from
L1 down run at roughly 1 request/second — indistinguishable from a normal
customer on volume alone.

| Level | Evasion | Rate | Detected | Flags | Top signals |
|---|---|---|---|---|---|
| **L0** | none — high volume | 20/s | ✅ caught | 4/10 | `iat_burstiness(27.3)`, `near_dup_rate(7.0)`, `herdan_c(5.7)` |
| **L1** | throttled to human pace | 1.0/s | ✅ caught | 3/10 | `iat_burstiness(36.4)`, `near_dup_rate(7.0)`, `herdan_c(6.0)` |
| **L2** | throttled + timing jitter | 1.0/s | ✅ caught | 7/10 | `conf_p10(85.3)`, `iat_burstiness(24.5)`, `near_dup_rate(7.0)` |
| **L3** | throttled + Poisson arrivals | 1.0/s | ✅ caught | 5/10 | `near_dup_rate(7.0)`, `herdan_c(5.3)`, `len_cv(4.5)` |
| **L4** | split across 5 API keys + Poisson | 0.24/s each | ✅ 5/5 caught | 2–5/10 | `near_dup_rate`, `herdan_c`, `conf_p10` |
| **L5** | natural-looking text + Poisson | 1.0/s | ✅ caught | 4/10 | `conf_p10(20.0)`, `iat_burstiness(7.9)`, `near_dup_rate(5.6)` |

Benign clients over the same run:

| Client | Flags | Verdict |
|---|---|---|
| `customer-0` | 0/10 | benign |
| `customer-1` | 0/10 | benign |
| `customer-2` | 0/10 | benign |
| `customer-3` | 1/10 | benign (needs 2 to flag) |

The L4 row is the one worth dwelling on. Splitting a campaign across five keys
at a quarter of a request per second each defeats every rate limit anyone would
plausibly configure — and all five members were still flagged individually,
because the features measure query *shape* per window and do not care about
volume.

**L4 was also linked as a campaign** by `detector/campaign.py`, which grouped
the members and confirmed them on pooled traffic — though see Shortcomings for
how that linkage over-merges.

## Shortcomings

Stated plainly. Most of these are unresolved.

**The benign class is synthetic and too homogeneous.** All benign traffic comes
from one template-based generator. Real user traffic is messier in ways that
would produce false positives this testbed cannot show. **The 0% false-positive
rate above is close to meaningless** — treat it as a lower bound on a number
that is genuinely unknown. Four benign clients is not a sample.

**`conf_p10` and `iat_burstiness` do a lot of the work, and both are fragile.**
DistilBERT SST-2 is extremely confident on ordinary text (>0.99 routinely),
which makes probing queries stand out sharply; a better-calibrated victim model
would weaken `conf_p10` substantially. `iat_burstiness` relies on the benign
clients' bursty pacing, which is a property of the generator as much as of real
humans.

**Automated is not the same as attacking.** A legitimate machine-paced
integration sending perfectly ordinary sentences was flagged in earlier
testing. Adding a few service accounts to a human baseline does *not* fix it —
a minority cannot move a median. Calibrating a **separate baseline per client
class** does: the same client scored 2 flags (ATTACK) against a human baseline
and 0 flags (benign) against a service-account baseline, with attack recall
unchanged. This is an operational requirement, not an optional refinement.

**Cross-key linkage over-merges and is evadable.** In the run above it merged
L0–L4 into a single group of eight, because they all derive from the same
attack corpus — it answers "same tooling?", not "same actor?". In earlier
testing a campaign that partitioned its grid with coprime strides was not
linked at all, because partitioning makes members' queries *complementary*
rather than overlapping — the opposite of what similarity linkage looks for.

**Partial windows are not scored.** A client with fewer than 30 requests is
reported as *insufficient*, not guessed at. This was found the hard way: live
scoring of an in-flight window gave a benign customer `iat_burstiness` z=37 at
12 requests, which settled to z=10 once the window filled. Features are not
comparable across window lengths, so a live detector needs one full window
before it can say anything — roughly 20 seconds at 1.5 req/s.

**Small samples throughout.** 30-request windows, 1–2 windows per client, 8
calibration windows. Ratios estimated from 30 samples are noisy and the
baseline's spread estimates are rough.

**The attacks are the ones we thought of.** Benign-only calibration limits how
much this biases results — the detector never sees an attack sample — but does
not eliminate it. An attacker drawing from a genuinely varied real corpus at
human pace has not been tested, and margins at L5 (4 flags, z-scores 3.7–20)
are thin enough that it might pass.

**Docker is unverified.** See the note in Quickstart.

## Team

Adwait M. — <https://github.com/adwaitm0106>
