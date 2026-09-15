Stolen copy agreement with the victim on 1000 held-out real texts. Always guessing the most common label scores 54.1%.

**Response modes** (attacker keeps all 2000 pairs)

| Response mode | Copy trained on labels | Copy weighted by confidence |
|---|---|---|
| `full` | 72.6% | 72.5% |
| `label` | 72.6% | 72.6% |
| `rounded` | 72.6% | 72.5% |

**Pairs harvested** (mean of 5 random samples, full responses)

| Pairs | Copy trained on labels | Copy weighted by confidence |
|---|---|---|
| 25 | 52.9% (+/- 3.7) | 53.0% (+/- 4.1) |
| 50 | 55.7% (+/- 5.3) | 55.9% (+/- 5.2) |
| 100 | 60.1% (+/- 2.7) | 59.6% (+/- 2.5) |
| 200 | 62.5% (+/- 2.4) | 62.9% (+/- 2.6) |
| 400 | 64.8% (+/- 0.6) | 65.1% (+/- 0.5) |
| 800 | 68.8% (+/- 0.9) | 69.3% (+/- 1.2) |
| 1600 | 71.5% (+/- 0.7) | 71.8% (+/- 0.6) |
| 2000 | 72.6% (+/- 0.0) | 72.5% (+/- 0.0) |

**Per-key budget against an attacker with several keys**

| Budget per key | Keys | Pairs collected | Copy agreement |
|---|---|---|---|
| 50 | 1 | 50 | 55.9% |
| 50 | 5 | 250 | 64.0% |
| 50 | 20 | 1000 | 69.7% |
| 100 | 1 | 100 | 59.6% |
| 100 | 5 | 500 | 65.0% |
| 100 | 20 | 2000 | 72.5% |
| 200 | 1 | 200 | 62.9% |
| 200 | 5 | 1000 | 69.7% |
| 200 | 20 | 2000 | 72.5% |
