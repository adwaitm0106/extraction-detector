Baseline: 24 windows from 8 real customers. Flag at z >= 3.5 on >= 2 signals.

| Client | Group | Requests | Signals | Verdict | Strongest signals |
|---|---|---|---|---|---|
| `atk-probe-yelp` | attacker | 60 | 5 | ATTACK | edit_neighbour_rate (30.0), herdan_c (11.9), label_balance (6.1) |
| `atk-probe-twitter` | attacker | 60 | 4 | ATTACK | edit_neighbour_rate (30.0), herdan_c (12.5), label_balance (8.8) |
| `atk-template-boundary` | attacker | 60 | 3 | ATTACK | edit_neighbour_rate (30.0), herdan_c (11.7), near_dup_rate (5.3) |
| `atk-harvest-mixed` | attacker | 60 | 0 | benign | none |
| `atk-harvest-split-a` | attacker | 30 | 0 | benign | none |
| `atk-harvest-split-b` | attacker | 30 | 0 | benign | none |
| `atk-harvest-split-c` | attacker | 30 | 0 | benign | none |
| `atk-harvest-split-d` | attacker | 30 | 0 | benign | none |
| `atk-harvest-split-e` | attacker | 30 | 0 | benign | none |
| `atk-harvest-yelp` | attacker | 60 | 0 | benign | none |
| `cust-reddit-0` | benign (seen source) | 60 | 1 | benign | low_conf_rate (4.3) |
| `cust-twitter-1` | benign (seen source) | 60 | 1 | benign | iat_burstiness (3.6) |
| `cust-amazon-0` | benign (seen source) | 60 | 0 | benign | none |
| `cust-amazon-1` | benign (seen source) | 60 | 0 | benign | none |
| `cust-reddit-1` | benign (seen source) | 60 | 0 | benign | none |
| `cust-twitter-0` | benign (seen source) | 60 | 0 | benign | none |
| `cust-yelp-0` | benign (seen source) | 60 | 0 | benign | none |
| `cust-yelp-1` | benign (seen source) | 60 | 0 | benign | none |
| `cust-imdb-0` | benign (unseen source) | 60 | 1 | benign | low_conf_rate (3.8) |
| `cust-imdb-1` | benign (unseen source) | 60 | 1 | benign | low_conf_rate (3.8) |

Attackers caught: **3 of 10**. False alarms: **0 of 8** customers on seen sources, **0 of 2** on the unseen source.

| Signal | Fired on attackers | Fired on customers |
|---|---|---|
| `exact_dup_rate` | 0 / 10 | 0 / 10 |
| `near_dup_rate` | 3 / 10 | 0 / 10 |
| `herdan_c` | 3 / 10 | 0 / 10 |
| `token_entropy_norm` | 0 / 10 | 0 / 10 |
| `len_cv` | 0 / 10 | 0 / 10 |
| `template_share` | 0 / 10 | 0 / 10 |
| `low_conf_rate` | 0 / 10 | 3 / 10 |
| `conf_p10` | 1 / 10 | 0 / 10 |
| `iat_burstiness` | 0 / 10 | 1 / 10 |
| `label_balance` | 2 / 10 | 0 / 10 |
| `edit_neighbour_rate` | 3 / 10 | 0 / 10 |
