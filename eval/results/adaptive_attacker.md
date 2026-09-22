Boundary-probing attacker against the eleven-signal detector with the solo rule, 60 queries per round, fresh API key each round. Success is 3 consecutive unflagged rounds with unchanged tactics. Probe density is the share of queries that still have a close but different query among the others.

| Attacker | Trials | Fully evaded | First unflagged round (median, range) | Probe density: start, when evaded | Label flips per round: start, when evaded |
|---|---|---|---|---|---|
| sees which signals fired | 5 | 0 of 5 | never | 1.00, n/a | 0.8, n/a |
| sees only flagged or not, changes one tactic at random | 5 | 0 of 5 | never | 1.00, n/a | 0.8, n/a |
| no feedback, uses the countermeasures to the original ten signals | 5 | 0 of 5 | never | 1.00, n/a | 3.0, n/a |
| no feedback, also knows the countermeasures to the eleventh | 5 | 0 of 5 | never | 0.77, n/a | 10.0, n/a |
| no feedback, edits most of every seed so no probe stays close to it | 5 | 5 of 5 | 1 (1 to 1) | 0.01, 0.01 | 19.0, 14.4 |
| no feedback, knows everything, and splits each probe pair across two keys | 5 | 4 of 5 | 1 (1 to 2) | 1.00, 0.98 | 3.0, 3.2 |
| splits across two keys AND edits most of every seed | 5 | 5 of 5 | 1 (1 to 1) | 0.41, 0.39 | 7.0, 7.6 |

Split attacker: evaded the per-key detector in 4 of 5 trials, and evaded per-key scoring plus cross-key linkage in 0 of 5.

Split far attacker: evaded the per-key detector in 5 of 5 trials, and evaded per-key scoring plus cross-key linkage in 2 of 5.
