Rescored 10 attackers and 15 customers with signals removed. Baseline, cutoff (z >= 3.5) and rule (2 signals) unchanged.

| Signals used | Count | Attackers caught | Customers wrongly flagged |
|---|---|---|---|
| all signals | 10 | 10 of 10 | 1 of 15 |
| drop exact_dup_rate | 9 | 10 of 10 | 1 of 15 |
| drop near_dup_rate | 9 | 8 of 10 | 1 of 15 |
| drop herdan_c | 9 | 8 of 10 | 1 of 15 |
| drop token_entropy_norm | 9 | 10 of 10 | 1 of 15 |
| drop len_cv | 9 | 10 of 10 | 1 of 15 |
| drop template_share | 9 | 10 of 10 | 1 of 15 |
| drop low_conf_rate | 9 | 10 of 10 | 0 of 15 |
| drop conf_p10 | 9 | 10 of 10 | 0 of 15 |
| drop iat_burstiness | 9 | 10 of 10 | 1 of 15 |
| drop label_balance | 9 | 10 of 10 | 1 of 15 |
| drop confidence signals | 8 | 10 of 10 | 0 of 15 |
| content only | 6 | 10 of 10 | 0 of 15 |
| timing and labels only | 2 | 0 of 10 | 0 of 15 |
| confidence signals only | 2 | 1 of 10 | 1 of 15 |
