Median value of each signal per group, over every full window, next to the baseline learned from real customers.

| Signal | Baseline centre | Baseline spread | customers (seen) | customers (unseen) | probers | harvesters |
|---|---|---|---|---|---|---|
| `exact_dup_rate` | 0.200 | 0.074 | 0.200 | 0.200 | 0.033 | 0.000 |
| `near_dup_rate` | 0.350 | 0.124 | 0.383 | 0.350 | 1.000 | 0.000 |
| `herdan_c` | 0.892 | 0.015 | 0.886 | 0.882 | 0.710 | 0.904 |
| `token_entropy_norm` | 0.916 | 0.034 | 0.922 | 0.895 | 0.946 | 0.891 |
| `len_cv` | 0.322 | 0.090 | 0.334 | 0.218 | 0.318 | 0.278 |
| `template_share` | 0.067 | 0.033 | 0.100 | 0.083 | 0.133 | 0.033 |
| `low_conf_rate` | 0.067 | 0.099 | 0.050 | 0.033 | 0.000 | 0.033 |
| `conf_p10` | 0.938 | 0.080 | 0.946 | 0.927 | 0.981 | 0.941 |
| `iat_burstiness` | 0.033 | 0.060 | 0.028 | 0.047 | -0.085 | -0.042 |
| `label_balance` | 0.083 | 0.074 | 0.083 | 0.067 | 0.267 | 0.067 |

Strongest deviations for each harvest key. A client is flagged at z >= 3.5 on at least 2 signals.

| Key | Top three z-scores |
|---|---|
| `atk-harvest-mixed` | near_dup_rate 2.8, len_cv 2.8, exact_dup_rate 2.7 |
| `atk-harvest-split-a` | near_dup_rate 2.8, exact_dup_rate 2.7, iat_burstiness 1.3 |
| `atk-harvest-split-b` | near_dup_rate 2.8, exact_dup_rate 2.7, template_share 1.0 |
| `atk-harvest-split-c` | near_dup_rate 2.8, exact_dup_rate 2.7, conf_p10 2.1 |
| `atk-harvest-split-d` | near_dup_rate 2.8, exact_dup_rate 2.7, len_cv 1.3 |
| `atk-harvest-split-e` | near_dup_rate 2.8, exact_dup_rate 2.7, template_share 1.0 |
| `atk-harvest-yelp` | iat_burstiness 3.1, near_dup_rate 2.8, exact_dup_rate 2.7 |
