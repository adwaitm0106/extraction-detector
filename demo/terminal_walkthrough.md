# Terminal walkthrough

Real output from a full run of `demo\run_demo.ps1`, plus the large-scale
evaluation. Each stage below is a self-contained block, meant to be
screenshotted on its own.

Heartbeat lines that repeat every three seconds have been trimmed to the first
one, a `...` marker, and the last one before the next event. Nothing else has
been edited. Elapsed times in the headers are from a warm run (model already
downloaded); a cold first run adds a few minutes at stage 1.

Reproduce all of this with:

```
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```

---

## STAGE 1: The API is up and answering

Proves the victim model loaded and serves predictions, and that every request
lands in the log with the six fields the detector needs. `latency_ms` is model
inference time only.

```
$ curl.exe -s http://127.0.0.1:8000/health
{"status":"ok","model_loaded":true}

$ curl.exe -s -X POST http://127.0.0.1:8000/predict \
    -H "Content-Type: application/json" \
    -H "X-API-Key: demo-key-1" \
    -d "{\"input\":\"This movie was absolutely fantastic.\"}"
{"label":"POSITIVE","confidence":0.9998722076416016}

$ tail -1 data/logs/requests.jsonl
{"ts": 1789154032.2957852, "api_key": "demo-key-1", "input": "This movie was
absolutely fantastic.", "predicted_label": "POSITIVE", "confidence":
0.9998722076416016, "latency_ms": 54}
```

*(the log line is one line in the file; wrapped here to fit the page)*

---

## STAGE 2: Calibration, learning normal from benign traffic only

Proves the baseline is built from ordinary customers and nothing else. Four
clients at 45 requests each produce 8 windows of 30; the minimum to calibrate
at all is 5. No attack traffic exists at this point in the run, so the detector
cannot have learned any attack signature.

Elapsed: 0:13 to 1:27.

```
==========================================================================
  CALIBRATION: learning what normal looks like
==========================================================================

  Four ordinary customers, 45 queries each.
  The detector sees ONLY benign traffic here -- it never
  learns any attack signature. That is what keeps the
  evaluation honest.

  > fitting the baseline
calibrated on 8 benign windows from 4 clients -> thresholds.json
```

---

## STAGE 3: Phase 1, normal customers, no alerts

Proves the detector stays quiet on legitimate traffic. Two customers it has
never seen before (different random seeds from the calibration clients) send
30 requests each. Both score zero flags. The "collecting" lines show it
refusing to judge anyone until it has a full 30-request window.

Elapsed: 1:27 to 1:56.

```
==========================================================================
  PHASE 1: Normal traffic - watch the console
==========================================================================

  Two ordinary customers are now querying the API.
  The detector is watching live. Expect NO alerts.

  > two customers sending traffic; detector scoring live every 3s
  [23:11:12] 0 requests seen - collecting (need 30 per client before scoring)
  [23:11:15] 9 requests seen - collecting (need 30 per client before scoring)
  ...
  [23:11:34] 30 requests seen - collecting (need 30 per client before scoring)
  [23:11:38] 34 requests seen - collecting (need 30 per client before scoring)

  Phase 1 over: no alerts, as expected.
```

---

## STAGE 4: Phase 2, the attacker is caught and cut off

The important one. The attacker runs at the same speed as the customers above
(about 1.5 requests/second, Poisson-spaced so the timing looks human), so no
rate limit would fire. It is caught on query *shape* instead: four of ten
signals, each with its z-score and a plain-English reason. The two `all clean`
lines immediately before are the benign customers, still clean at the same
moment.

Elapsed: 1:56 to 2:18. The alert lands 22 seconds after the banner.

```
==========================================================================
  PHASE 2: Attacker starts now
==========================================================================

  Same rate as the customers above. Poisson-spaced, so the
  timing looks human too. The only difference is WHAT it asks:
  systematic probes around the model's decision boundary.

  Watch for the ALERT line, then the BLOCK line. After the block,
  every further request from that key is answered with HTTP 429.

  [23:11:41] 37 requests seen - collecting (need 30 per client before scoring)
  ...
  [23:11:54] 65 requests seen - collecting (need 30 per client before scoring)
  [23:11:57] 30 requests scored - all clean
  [23:12:00] 30 requests scored - all clean

  [ALERT 23:12:03] EXTRACTION SUSPECTED  api_key=extraction-attacker  flags=4/10  requests=36
      signals: near_dup_rate(7.0), herdan_c(5.3), len_cv(4.5), token_entropy_norm(3.6)
      why: sends many near-identical queries; uses an unusually narrow vocabulary;
           query lengths are unusually uniform; word choice is unnaturally uniform or skewed

  [BLOCK 23:12:03] api_key=extraction-attacker now gets HTTP 429 on every request
```

---

## STAGE 4b: The block worked, from the attacker's own point of view

Proves enforcement is real rather than cosmetic. The attacker tried to send 60
queries. It got answers to 36 and was refused 24 times. Its harvest stopped
mid-run.

Elapsed: 2:43.

```
  What the attacker saw from its side:
    sent 60 requests in 39.2s (1.5 req/s aggregate)
    status codes: {200: 36, 429: 24}
  (429 = throttled by the detector; 200 = got through before the block)
```

---

## STAGE 5: Final scoring and the blocklist the API is enforcing

Proves the verdicts and shows the actual enforcement state. One attacker
flagged with its evidence, both customers clean, and the blocklist file the API
reads on every request. The demo deletes this file on exit so nobody stays
throttled afterwards.

Elapsed: 2:44.

```
baseline: 8 benign windows, 4 clients, window=30 stride=15
rule: flag a feature at z >= 3.5; call ATTACK at >= 2 flags

api_key                reqs   wins   flags  verdict  features flagged
-----------------------------------------------------------------------------------
extraction-attacker      36      1       4   ATTACK  near_dup_rate(7.0), herdan_c(5.3), len_cv(4.5)
customer-0               30      1       0   benign
customer-1               30      1       0   benign

1 of 3 clients flagged.

  blocked.json (what the API is enforcing right now):
    {
      "updated": 1789153945.9552867,
      "blocked": {
        "extraction-attacker": {
          "since": 1789153923.6677868,
          "flags": ["near_dup_rate", "herdan_c", "len_cv", "token_entropy_norm"],
          "why": [
            "sends many near-identical queries",
            "uses an unusually narrow vocabulary",
            "query lengths are unusually uniform",
            "word choice is unnaturally uniform or unnaturally skewed"
          ]
        }
      }
    }

clients evaluated: 3

                 predicted
               attack  benign
actual attack       1       0
actual benign       0       2

precision 1.000   recall 1.000   f1 1.000
```

Three clients is a demo, not a measurement. Stage 6 is the real number.

---

## STAGE 6: The evasion ladder at scale

The actual evaluation: 1,200 requests, 25 clients, 15 benign and 10 attacker
keys, against a baseline learned from 8 separate benign clients with
deliberately mixed behaviour (slow, fast, bursty, Poisson-spaced,
machine-paced).

Every attacker here is throttled to roughly human speed except L0. `L4-split-*`
is one campaign divided across five API keys at about a quarter of a request
per second each, which defeats any realistic rate limit. All five were still
caught individually.

Reproduce with:

```
python detector/detector.py --log data/logs/eval_run.jsonl \
    --thresholds data/logs/eval_thresholds.json
```

```
baseline: 19 benign windows, 8 clients, window=30 stride=15
rule: flag a feature at z >= 3.5; call ATTACK at >= 2 flags

api_key                reqs   wins   flags  verdict  features flagged
-----------------------------------------------------------------------------------
L2-jittered              45      2       6   ATTACK  conf_p10(75.8), herdan_c(10.3), near_dup_rate(5.4)
L1-throttled             45      2       4   ATTACK  herdan_c(9.8), iat_burstiness(7.4), near_dup_rate(5.4)
L4-split-b               30      1       3   ATTACK  conf_p10(18.8), herdan_c(9.5), near_dup_rate(4.0)
L5-natural               45      2       3   ATTACK  conf_p10(18.3), near_dup_rate(4.0), herdan_c(3.9)
L4-split-d               30      1       3   ATTACK  conf_p10(15.3), herdan_c(5.5), near_dup_rate(5.1)
L0-noevasion             45      2       3   ATTACK  herdan_c(9.3), near_dup_rate(5.4), iat_burstiness(5.1)
L3-poisson               45      2       3   ATTACK  herdan_c(9.1), near_dup_rate(5.1), token_entropy_norm(3.7)
L4-split-c               30      1       3   ATTACK  herdan_c(8.4), near_dup_rate(4.7), token_entropy_norm(4.3)
cust-service-heavy       90      5       2   ATTACK  conf_p10(39.4), low_conf_rate(4.0)
L4-split-a               30      1       2   ATTACK  herdan_c(8.6), near_dup_rate(4.4)
L4-split-e               30      1       2   ATTACK  herdan_c(7.2), near_dup_rate(5.1)
cust-poisson-fast        45      2       1   benign  conf_p10(17.4)
cust-human-long          75      4       1   benign  template_share(4.0)
cust-service-1           45      2       1   benign  exact_dup_rate(4.7)
cust-human-3             45      2       1   benign  label_balance(4.7)
cust-human-heavy         90      5       0   benign
cust-poisson-2           60      3       0   benign
cust-poisson-slow        45      2       0   benign
cust-human-1             45      2       0   benign
cust-human-jittery       45      2       0   benign
cust-human-brief         30      1       0   benign
cust-poisson-1           45      2       0   benign
cust-service-2           60      3       0   benign
cust-human-2             60      3       0   benign
cust-human-slow-1        45      2       0   benign
```

---

## STAGE 6b: Detection rate and false-positive rate

10 of 10 attackers caught. 1 false alarm out of 15 benign clients.

```
clients evaluated: 25

                 predicted
               attack  benign
actual attack      10       0
actual benign       1      14

precision 0.909   recall 1.000   f1 0.952
false alarms:     cust-service-heavy
```

The false alarm is worth showing rather than hiding. `cust-service-heavy` is a
legitimate machine-paced integration sending 90 requests. It tripped on
confidence because two of its queries in one window came back at 0.55, and our
own benign generator had built self-contradicting sentences like *"the movie
left me cold I'd recommend it."* Part generator artefact, part a real effect:
heavy clients are judged on more windows, and the worst one counts.

---

## STAGE 7: Does blocking actually protect the model?

Proves the detector prevents theft rather than just noticing it. The attacker
is played for real: harvest query/answer pairs, train a copy, measure how often
the copy agrees with the victim on 300 sentences neither trained on. Run twice,
once unwatched and once with the detector enforcing through the same blocklist
the API reads.

Reproduce with `python eval/steal.py` (API running, baseline calibrated).

```
labelling 300 held-out sentences with the victim...
  done. always-guess-majority baseline: 53.3% agreement

run 1: attacker harvests 500 queries, no enforcement...
  harvested 500 pairs in 97s

run 2: same attacker, detector enforcing (429 once flagged)...
  cut off after 30 queries; 30 usable pairs harvested (4s)

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

Unwatched, the stolen copy is wrong about one time in eighty. Blocked at 30
queries, it is wrong about one time in eight. A tenfold difference in error
rate. Caveat worth stating out loud: the held-out sentences share the
attacker's template family and the student is deliberately tiny, so 87% is
generous to the attacker. The gap is the result, not the absolute numbers.
