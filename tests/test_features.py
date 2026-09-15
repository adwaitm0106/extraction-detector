"""The ten signals, and the windowing that feeds them."""

import random

import pytest

from features import (
    FEATURE_NAMES,
    PROPORTION_FEATURES,
    compute_features,
    group_by_key,
    windows,
)


def rows(texts, gaps=None, labels=None, key="k"):
    out, t = [], 0.0
    for i, text in enumerate(texts):
        t += gaps[i] if gaps else 1.0
        out.append({"ts": t, "api_key": key, "input": text,
                    "predicted_label": labels[i] if labels else "POSITIVE",
                    "confidence": 0.99})
    return out


def test_partial_windows_are_dropped():
    assert windows(list(range(29)), 30, 15) == []
    assert len(windows(list(range(30)), 30, 15)) == 1
    assert len(windows(list(range(60)), 30, 15)) == 3
    assert all(len(w) == 30 for w in windows(list(range(75)), 30, 15))


def test_proportion_features_are_real_features():
    assert PROPORTION_FEATURES <= set(FEATURE_NAMES)


def test_every_feature_is_computed():
    f = compute_features(rows(["query number %d here" % i for i in range(30)]))
    assert set(f) == set(FEATURE_NAMES)


def test_identical_queries_are_all_duplicates():
    f = compute_features(rows(["the movie was good"] * 30))
    assert f["near_dup_rate"] == 1.0
    assert f["exact_dup_rate"] == pytest.approx(1 - 1 / 30)


def test_unrelated_queries_have_no_duplicates():
    rng = random.Random(1)
    texts = [" ".join("w%d" % rng.randrange(10 ** 6) for _ in range(6)) for _ in range(30)]
    f = compute_features(rows(texts))
    assert f["near_dup_rate"] == 0.0
    assert f["exact_dup_rate"] == 0.0


def test_metronome_timing_scores_minus_one():
    f = compute_features(rows(["q %d x y" % i for i in range(30)], gaps=[1.0] * 30))
    assert f["iat_burstiness"] == pytest.approx(-1.0)


def test_bursty_timing_scores_positive():
    gaps = [0.05 if i % 5 else 20.0 for i in range(30)]
    f = compute_features(rows(["q %d x y" % i for i in range(30)], gaps=gaps))
    assert f["iat_burstiness"] > 0


def test_label_balance_extremes():
    texts = ["q %d a b" % i for i in range(30)]
    even = compute_features(rows(texts, labels=["POSITIVE", "NEGATIVE"] * 15))
    one_sided = compute_features(rows(texts, labels=["POSITIVE"] * 30))
    assert even["label_balance"] == 0.0
    assert one_sided["label_balance"] == 0.5


def test_group_by_key_splits_and_sorts_by_time():
    data = [{"ts": 3, "api_key": "a"}, {"ts": 1, "api_key": "a"}, {"ts": 2, "api_key": "b"}]
    grouped = group_by_key(data)
    assert set(grouped) == {"a", "b"}
    assert [r["ts"] for r in grouped["a"]] == [1, 3]
