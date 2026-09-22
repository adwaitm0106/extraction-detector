Boundary-probing attacker against the eleven-signal detector, 60 queries per round, fresh API key each round. Success is 3 consecutive unflagged rounds with unchanged tactics. Probe density is the share of queries that still have a close but different query among the others.

| Attacker | Trials | Fully evaded | First unflagged round (median, range) | Probe density: start, when evaded | Label flips per round: start, when evaded |
|---|---|---|---|---|---|
| sees which signals fired | 5 | 5 of 5 | 3 (3 to 4) | 1.00, 0.89 | 1.0, 7.6 |
| sees only flagged or not, changes one tactic at random | 5 | 0 of 5 | never | 1.00, n/a | 1.0, n/a |
| no feedback, uses the countermeasures to the original ten signals | 5 | 3 of 5 | 1 (1 to 1) | 1.00, 1.00 | 3.0, 1.7 |
| no feedback, also knows the countermeasures to the eleventh | 5 | 2 of 5 | 1 (1 to 2) | 0.83, 0.84 | 10.2, 14.0 |
| no feedback, knows everything, and splits each probe pair across two keys | 5 | 5 of 5 | 1 (1 to 1) | 0.99, 0.99 | 3.2, 3.6 |

Split attacker: evaded the per-key detector in 5 of 5 trials, and evaded per-key scoring plus cross-key linkage in 0 of 5.
