"""A deterministic stand-in for the real model, for tests and CI.

Loading DistilBERT needs torch and a 268 MB download, which is far too heavy
for a test run on every push. Set MODEL_STUB=1 and the API answers from a tiny
word list instead, so everything around the model (validation, logging,
blocking, budgets, response modes) can be tested without it.

The stub is not a sentiment model. Never use it for results.
"""

_POSITIVE = {"good", "great", "love", "excellent", "fantastic", "wonderful",
             "best", "happy", "amazing", "nice", "enjoyed", "recommend"}
_NEGATIVE = {"bad", "terrible", "hate", "awful", "worst", "boring", "poor",
             "sad", "horrible", "waste", "disappointing", "broken"}


class StubPipeline:
    """Called like a transformers pipeline: stub(text, **kwargs) -> [result]."""

    def __call__(self, text, **kwargs):
        words = [w.strip(".,!?;:\"'()").lower() for w in text.split()]
        score = sum(w in _POSITIVE for w in words) - sum(w in _NEGATIVE for w in words)
        label = "POSITIVE" if score >= 0 else "NEGATIVE"
        confidence = min(0.99, 0.6 + 0.1 * abs(score))
        return [{"label": label, "score": confidence}]
