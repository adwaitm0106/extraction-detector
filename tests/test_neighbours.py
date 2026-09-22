"""edit_neighbour_rate: catching a query and its edited copy, and only that."""

import random

from features import (
    EDIT_NEIGHBOUR_RATIO,
    WIDE_EXTRA,
    _edit_neighbour_rate,
    compute_features,
    windows_with_context,
)

SEED = "the service at this restaurant was really quite good and the staff were kind"


def edit(text, position, replacement):
    words = text.split()
    words[position] = replacement
    return " ".join(words)


def unrelated(n, seed=0):
    rng = random.Random(seed)
    vocab = ["w%d" % i for i in range(5000)]
    return [" ".join(rng.sample(vocab, rng.randint(6, 14))) for _ in range(n)]


def rows(texts):
    return [{"ts": float(i), "api_key": "k", "input": t, "predicted_label": "POSITIVE",
             "confidence": 0.95} for i, t in enumerate(texts)]


def test_unrelated_queries_have_no_neighbours():
    assert _edit_neighbour_rate(unrelated(60)) == 0.0


def test_identical_queries_are_not_edit_neighbours():
    assert _edit_neighbour_rate([SEED] * 30) == 0.0


def test_a_query_and_its_edited_copy_are_neighbours():
    assert _edit_neighbour_rate([SEED, edit(SEED, 4, "awful")] + unrelated(8)) == 2 / 10


def test_several_edits_still_count():
    text = SEED
    for pos, word in ((2, "xx"), (6, "yy"), (10, "zz")):
        text = edit(text, pos, word)
    assert _edit_neighbour_rate([SEED, text]) == 1.0


def test_heavy_reuse_of_a_few_seeds_is_still_caught():
    """A signal that only looked at rare words would miss this."""
    seeds = unrelated(3, seed=1)
    texts = [edit(seeds[i % 3], i % 5, "zz%d" % i) for i in range(45)]
    assert _edit_neighbour_rate(texts) == 1.0


def test_edits_past_the_threshold_are_not_neighbours():
    text = " ".join("changed%d" % i if i % 2 == 0 else w
                    for i, w in enumerate(SEED.split()))
    assert _edit_neighbour_rate([SEED, text]) == 0.0


def test_the_threshold_is_the_documented_one():
    assert EDIT_NEIGHBOUR_RATIO == 0.6


def test_the_wide_span_sees_pairs_kept_far_apart():
    """A prober keeps a query and its edited copy more than 30 requests apart."""
    seeds = unrelated(30, seed=2)
    texts = seeds + [edit(s, 1, "probe%d" % i) for i, s in enumerate(seeds)]
    data = rows(texts)
    narrow = compute_features(data[30:], wide=None)["edit_neighbour_rate"]
    wide = compute_features(data[30:], wide=data)["edit_neighbour_rate"]
    assert narrow == 0.0
    assert wide == 1.0


def test_windows_with_context_adds_history_before_each_window():
    data = list(range(100))
    pairs = windows_with_context(data, 30, 15)
    first_window, first_wide = pairs[0]
    last_window, last_wide = pairs[-1]
    assert first_wide == first_window == data[:30]
    assert len(last_wide) == 30 + WIDE_EXTRA and last_wide[-30:] == last_window
    assert windows_with_context(data[:29], 30, 15) == []
