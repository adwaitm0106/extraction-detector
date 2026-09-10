"""Query sources for the traffic generator.

No external dataset: every query is produced from templates and word lists
here. That keeps generation offline, deterministic under a seed, and free of
a download step in the demo. The tradeoff is that benign traffic is less
linguistically varied than a real review corpus would be, so absolute
detector numbers should be read as directional rather than as a benchmark.
"""

import random
import string

# --- Benign material: short opinion sentences of the kind a sentiment API
# --- would legitimately serve. Assembled from parts so repeats occur
# --- naturally, as they do in real traffic.
SUBJECTS = [
    "the movie", "this film", "the acting", "the plot", "the soundtrack",
    "the ending", "the cinematography", "the script", "the pacing", "the cast",
    "this restaurant", "the service", "the food", "the delivery", "the app",
    "the update", "customer support", "the battery life", "the screen",
]
OPINIONS_POS = [
    "was fantastic", "really impressed me", "exceeded my expectations",
    "was well worth it", "genuinely surprised me", "was a delight",
    "held up beautifully", "was better than I hoped", "made my week",
]
OPINIONS_NEG = [
    "was a complete letdown", "wasted my time", "fell apart halfway through",
    "was painfully slow", "disappointed me", "was not worth the money",
    "made no sense at all", "left me cold", "needs serious work",
]
CLOSERS = [
    "", "", "", ".", "!", ", honestly.", ", to be fair.",
    " I'd recommend it.", " I would not go back.", " Mixed feelings overall.",
]

# --- Attack material: a small vocabulary sampled uniformly produces text with
# --- no sentence structure. This is the classic extraction pattern -- the
# --- attacker wants coverage of the input space, not plausible sentences.
OOD_VOCAB = [
    "quantum", "ledger", "banana", "velocity", "trombone", "seldom", "gravel",
    "petunia", "asymptote", "wharf", "lantern", "cobalt", "murmur", "thicket",
    "sprocket", "verdant", "kiosk", "fathom", "brisk", "nimbus", "tangent",
    "cinder", "ravine", "quartz", "plume", "harrow", "sable", "jetty",
]
PROBE_SEEDS = [
    "the movie was good",
    "i did not enjoy this at all",
    "it was fine i suppose",
    "an absolute masterpiece from start to finish",
    "boring and far too long",
]


def benign_query(rng: random.Random) -> str:
    """A plausible user query. Positive and negative in rough balance."""
    subject = rng.choice(SUBJECTS)
    opinion = rng.choice(OPINIONS_POS if rng.random() < 0.55 else OPINIONS_NEG)
    return f"{subject} {opinion}{rng.choice(CLOSERS)}"


def random_ood_query(rng: random.Random) -> str:
    """Uniform word salad: broad input-space coverage, no natural structure."""
    return " ".join(rng.choice(OOD_VOCAB) for _ in range(rng.randint(6, 20)))


def boundary_probe_query(rng: random.Random) -> str:
    """A seed sentence with one small perturbation.

    Near-duplicate queries are how an attacker maps a decision boundary: hold
    almost everything fixed and vary one token to find where the label flips.
    """
    words = rng.choice(PROBE_SEEDS).split()
    i = rng.randrange(len(words))
    mode = rng.random()
    if mode < 0.4:  # substitute
        words[i] = rng.choice(OOD_VOCAB)
    elif mode < 0.7:  # delete
        words.pop(i)
    elif mode < 0.9:  # duplicate
        words.insert(i, words[i])
    else:  # character-level typo
        w = words[i]
        j = rng.randrange(len(w))
        words[i] = w[:j] + rng.choice(string.ascii_lowercase) + w[j + 1:]
    return " ".join(words) or "the"


def sweep_query(index: int) -> str:
    """Deterministic grid over a template. Systematic, exhaustive, ordered.

    Distinct from the random profiles: an attacker enumerating a template
    produces queries with near-identical structure in a predictable sequence.
    """
    a = OOD_VOCAB[index % len(OOD_VOCAB)]
    b = SUBJECTS[(index // len(OOD_VOCAB)) % len(SUBJECTS)]
    return f"{b} was very {a}"
