| | distilbert | roberta |
|---|---|---|
| Labels the model returns | NEGATIVE, POSITIVE | negative, neutral, positive |
| Median confidence on real customer text | 0.998 | 0.839 |
| Answers at 99% confidence or higher | 73.0% | 0.0% |
| Answers below 90% confidence | 6.7% | 65.3% |
| Baseline centre for 10th percentile confidence | 0.938 | 0.511 |
| Baseline spread for 10th percentile confidence | 0.080 | 0.053 |

| Detector result | distilbert | roberta |
|---|---|---|
| Attackers caught, all signals | 3 of 10 | 3 of 10 |
| Customers wrongly flagged, seen sources | 0 of 8 | 0 of 8 |
| Customers wrongly flagged, unseen source | 0 of 2 | 0 of 2 |
| Attackers caught, drop confidence signals | 3 of 10 | 3 of 10 |
| Attackers caught, content only | 3 of 10 | 3 of 10 |
| Attackers caught, confidence signals only | 0 of 10 | 0 of 10 |
