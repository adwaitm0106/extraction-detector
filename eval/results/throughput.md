Measured on: Windows, Intel64 Family 6 Model 154 Stepping 4, GenuineIntel, 12 logical CPUs, Python 3.14.0.

**Detector** (parse, group, signals, flag rule; no API or model involved)

| Requests in log | Log size | Parse | Group | Score | Total | Throughput |
|---|---|---|---|---|---|---|
| 10,000 | 2.0 MB | 0.05s | 0.00s | 0.27s | 0.32s | 31,584 requests/s |
| 100,000 | 20.3 MB | 0.37s | 0.02s | 4.51s | 4.90s | 20,424 requests/s |
| 500,000 | 101.5 MB | 1.80s | 0.11s | 19.66s | 21.57s | 23,175 requests/s |

Computing the ten signals for one 30-request window takes 0.42 ms.

**Live `--watch` cycle** on a 100,000-request log: a full rescan takes 3.15s, reading only the new lines and rescoring the three clients that sent them takes 41.8 ms.

**API serving path** (stub model, so this excludes inference)

| Log durability | Requests/s | p50 latency | p95 latency |
|---|---|---|---|
| fsync every line (default) | 596 | 14.1 ms | 20.2 ms |
| no fsync | 749 | 8.8 ms | 18.0 ms |

**Real model ceiling.** Inference takes a median of 76 ms per request and runs one request at a time under a lock, so DistilBERT on this CPU tops out near 13 requests/s regardless of the API's own speed.
