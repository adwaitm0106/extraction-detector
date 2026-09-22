"""Calibration and scoring: the baseline, the flag rule and the blocklist."""

import json
import random

import pytest
from calibrate import MIN_SCALE, fit
from features import (
    FEATURE_NAMES,
    PROPORTION_FEATURES,
    compute_features,
    windows_with_context,
)
from score import (
    EXPLAIN,
    MIN_FLAGS,
    SOLO_SIGNALS,
    Z_SOLO,
    score_client,
    score_window,
    write_blocklist,
)

WINDOW, STRIDE = 30, 15
WORDS = ("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi "
         "omicron pi rho sigma tau upsilon phi chi psi omega").split()


def customer(rng, key="customer", n=60):
    """Varied queries, mixed labels, bursty timing."""
    out, t = [], 0.0
    for _ in range(n):
        words = rng.randint(4, 9)
        text = " ".join("%s%d" % (rng.choice(WORDS), rng.randrange(1000)) for _ in range(words))
        t += rng.choice((0.2, 0.3, 0.5, 4.0, 6.0))
        out.append({"ts": t, "api_key": key, "input": text,
                    "predicted_label": rng.choice(("POSITIVE", "NEGATIVE")),
                    "confidence": rng.uniform(0.85, 0.999)})
    return out


def prober(key="prober", n=60):
    """Near-copies of one sentence, one label, clockwork timing."""
    variants = ("the movie was good", "the movie was great", "the film was good")
    return [{"ts": float(i), "api_key": key, "input": variants[i % 3],
             "predicted_label": "POSITIVE", "confidence": 0.99} for i in range(n)]


@pytest.fixture(scope="module")
def baseline():
    rng = random.Random(7)
    samples = [compute_features(w, rng, wide=wide)
               for c in range(20)
               for w, wide in windows_with_context(customer(random.Random(100 + c)), WINDOW, STRIDE)]
    return fit(samples, WINDOW)


def test_every_feature_has_a_plain_english_reason():
    assert set(EXPLAIN) == set(FEATURE_NAMES)


def test_constant_features_get_a_floored_scale():
    samples = [{f: 0.0 for f in FEATURE_NAMES} for _ in range(10)]
    base = fit(samples, WINDOW)
    for f in FEATURE_NAMES:
        expected = 1.0 / WINDOW if f in PROPORTION_FEATURES else MIN_SCALE
        assert base[f]["scale"] == pytest.approx(expected)


def test_prober_is_flagged(baseline):
    r = score_client(prober(), baseline, WINDOW, STRIDE, random.Random(0))
    assert r["verdict"] == "ATTACK"
    assert r["n_flags"] >= MIN_FLAGS


@pytest.mark.parametrize("seed", [900, 901, 902])
def test_new_customer_is_not_flagged(baseline, seed):
    r = score_client(customer(random.Random(seed)), baseline, WINDOW, STRIDE, random.Random(0))
    assert r["verdict"] == "benign", r["flags"]


def test_client_below_one_window_is_not_judged(baseline):
    assert score_client(prober(n=29), baseline, WINDOW, STRIDE, random.Random(0)) is None


def test_blocklist_holds_only_attackers_and_keeps_block_time(tmp_path, baseline):
    path = tmp_path / "blocked.json"
    rng = random.Random(0)
    verdicts = {
        "prober": score_client(prober(), baseline, WINDOW, STRIDE, rng),
        "customer": score_client(customer(random.Random(900)), baseline, WINDOW, STRIDE, rng),
    }
    write_blocklist(str(path), verdicts)
    first = json.loads(path.read_text(encoding="utf-8"))["blocked"]
    assert set(first) == {"prober"}
    assert first["prober"]["why"]

    write_blocklist(str(path), verdicts)
    again = json.loads(path.read_text(encoding="utf-8"))["blocked"]
    assert again["prober"]["since"] == first["prober"]["since"]


def centred(baseline, **overrides):
    """A window whose every signal sits exactly at the baseline centre, except those given."""
    feats = {f: baseline[f]["centre"] for f in FEATURE_NAMES}
    feats.update(overrides)
    return feats


def test_the_edit_neighbour_signal_can_flag_a_window_on_its_own(baseline):
    r = score_window(centred(baseline, edit_neighbour_rate=0.6), baseline)
    assert r["flags"] == ["edit_neighbour_rate"]
    assert r["n_flags"] < MIN_FLAGS
    assert r["attack"] is True


def test_a_weaker_edit_neighbour_deviation_is_not_enough_alone(baseline):
    """Past the ordinary cutoff but short of the solo one, it needs a second signal."""
    scale = baseline["edit_neighbour_rate"]["scale"]
    centre = baseline["edit_neighbour_rate"]["centre"]
    r = score_window(centred(baseline, edit_neighbour_rate=centre + 4.0 * scale), baseline)
    assert r["flags"] == ["edit_neighbour_rate"] and r["attack"] is False
    r2 = score_window(centred(baseline, edit_neighbour_rate=centre + 4.0 * scale,
                              herdan_c=baseline["herdan_c"]["centre"]
                              + 4.0 * baseline["herdan_c"]["scale"]), baseline)
    assert r2["attack"] is True


def test_one_extreme_ordinary_signal_is_still_not_enough(baseline):
    for name in ("label_balance", "conf_p10", "iat_burstiness", "near_dup_rate"):
        r = score_window(centred(baseline, **{name: baseline[name]["centre"]
                                              + 30 * baseline[name]["scale"]}), baseline)
        assert r["flags"] == [name] and r["attack"] is False, name


def test_only_the_edit_neighbour_signal_may_flag_alone():
    assert SOLO_SIGNALS == ("edit_neighbour_rate",)
    assert Z_SOLO == 5.0


def test_a_client_verdict_uses_the_solo_rule(baseline):
    """End to end: score_client reports ATTACK when a window is attacked on one signal."""
    rows = prober()
    r = score_client(rows, baseline, WINDOW, STRIDE, random.Random(0))
    assert r["verdict"] == "ATTACK"
