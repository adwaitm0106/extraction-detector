"""Real corpora: cleaning, stable pool assignment and query perturbation.

None of this needs the `datasets` package; it is only imported when building.
"""

import random

from real_corpus import MAX_CHARS, MIN_WORDS, clean, perturb_query, pool_for


def test_clean_strips_markup_and_extra_whitespace():
    assert clean("Great<br /><br />movie,   really   good!") == "Great movie, really good!"


def test_clean_rejects_short_text_and_non_strings():
    assert clean("too short") is None
    assert clean(None) is None
    assert clean(123) is None


def test_long_text_is_cut_at_a_sentence_boundary():
    text = " ".join("This is sentence number %d of the review." % i for i in range(20))
    out = clean(text)
    assert len(out) <= MAX_CHARS
    assert out.endswith(".")
    assert len(out.split()) >= MIN_WORDS


def test_pool_assignment_is_stable_and_ignores_case():
    assert pool_for("Hello World, great film") == pool_for("hello world, GREAT film")
    assert pool_for("some text here") == pool_for("some text here")


def test_pools_split_roughly_40_40_20():
    rng = random.Random(3)
    counts = {"calib": 0, "eval": 0, "attack": 0}
    n = 5000
    for _ in range(n):
        counts[pool_for("text %d %d" % (rng.randrange(10 ** 9), rng.randrange(10 ** 9)))] += 1
    assert 0.36 < counts["calib"] / n < 0.44
    assert 0.36 < counts["eval"] / n < 0.44
    assert 0.16 < counts["attack"] / n < 0.24


def test_perturbation_changes_at_most_one_word():
    rng = random.Random(5)
    base = "the service at this restaurant was really quite good"
    vocab = ["bad", "slow", "great", "cold"]
    for _ in range(300):
        out = perturb_query(base, rng, vocab)
        assert isinstance(out, str) and out
        assert abs(len(out.split()) - len(base.split())) <= 1
