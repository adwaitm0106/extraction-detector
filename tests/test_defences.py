"""Response shaping and per-key query budgets."""

import threading

import pytest

from defences import RESPONSE_MODES, QueryBudget, shape_response


def test_full_mode_returns_label_and_confidence():
    assert shape_response("POSITIVE", 0.9876, "full") == {"label": "POSITIVE", "confidence": 0.9876}


def test_label_mode_hides_confidence():
    assert shape_response("NEGATIVE", 0.61, "label") == {"label": "NEGATIVE"}


def test_rounded_mode_rounds_to_one_decimal():
    assert shape_response("POSITIVE", 0.9876, "rounded") == {"label": "POSITIVE", "confidence": 1.0}
    assert shape_response("POSITIVE", 0.64, "rounded")["confidence"] == 0.6


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        shape_response("POSITIVE", 0.9, "fuzzy")


def test_every_listed_mode_works():
    for mode in RESPONSE_MODES:
        assert shape_response("POSITIVE", 0.9, mode)["label"] == "POSITIVE"


def test_zero_budget_means_unlimited():
    budget = QueryBudget(0)
    assert not budget.enabled
    assert all(budget.allow("k") for _ in range(1000))


def test_budget_refuses_past_the_limit_for_each_key():
    budget = QueryBudget(3)
    assert [budget.allow("a") for _ in range(5)] == [True, True, True, False, False]
    assert budget.allow("b") is True
    assert budget.used("a") == 3
    assert budget.used("b") == 1


def test_negative_budget_is_rejected():
    with pytest.raises(ValueError):
        QueryBudget(-1)


def test_budget_is_exact_under_concurrent_requests():
    budget = QueryBudget(100)
    allowed = []

    def hammer():
        for _ in range(50):
            allowed.append(budget.allow("k"))

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(allowed) == 100
