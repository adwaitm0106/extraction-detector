"""Response-side defences against model extraction.

Detection catches attackers who probe the model, but not passive harvesters
sending ordinary text (see eval/results/real_data.md). These defences act on
what the API returns rather than on who is asking, so they apply to every
client equally, harvesters included.

    RESPONSE_MODE   full      label and confidence (default)
                    label     label only
                    rounded   confidence rounded to one decimal place
    QUERY_BUDGET    requests allowed per API key; 0 means unlimited (default)

shape_response() is shared with eval/defend_real.py, so the experiment measures
exactly the transformation the API applies. Standard library only.
"""

import threading
from collections import defaultdict

RESPONSE_MODES = ("full", "label", "rounded")


def shape_response(label, confidence, mode="full"):
    """What a client is shown for one prediction under a given response mode."""
    if mode == "full":
        return {"label": label, "confidence": confidence}
    if mode == "label":
        return {"label": label}
    if mode == "rounded":
        return {"label": label, "confidence": round(confidence, 1)}
    raise ValueError("unknown response mode %r; expected one of: %s"
                     % (mode, ", ".join(RESPONSE_MODES)))


class QueryBudget:
    """Counts served requests per API key and refuses them past a fixed limit.

    Kept in memory and per process, so it resets on restart and is not shared
    across replicas. A production budget would live in a shared store with a
    rolling time window; this is enough to measure what a budget is worth.
    """

    def __init__(self, limit):
        self.limit = int(limit)
        if self.limit < 0:
            raise ValueError("QUERY_BUDGET must be 0 (unlimited) or a positive integer")
        self._counts = defaultdict(int)
        self._lock = threading.Lock()

    @property
    def enabled(self):
        return self.limit > 0

    def allow(self, key):
        """Record one request for `key`. Returns False once its budget is spent."""
        if not self.enabled:
            return True
        with self._lock:
            if self._counts[key] >= self.limit:
                return False
            self._counts[key] += 1
            return True

    def used(self, key):
        with self._lock:
            return self._counts[key]
