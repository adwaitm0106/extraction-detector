# Video script

Two and a half minutes of talking over `demo\run_demo.ps1`. Times are from
pressing Enter. Follow the banners on screen, not the clock.

Before recording: run the demo once so the model is cached, make the font big,
and have `eval/figures/` open in another window for the end.

---

**Before you press Enter**

> If you sell access to a model through an API, someone can steal it just by
> using it. Send inputs, save the answers, train a copy. Your logs show a
> customer. The usual defence is a rate limit, but that only stops people in a
> hurry. So we built something that looks at *what* people ask, not how much.

Press Enter.

---

**0:13 - API ready**

> That's the victim, a sentiment model. Every request gets logged: who asked,
> what they asked, what it answered.

---

**0:13 to 1:27 - Calibration** (long quiet stretch, fill it)

> It's watching four normal customers to learn what normal looks like. It never
> sees an attack while learning, which is the whole point. It can't memorise
> our attacks because it's never shown one.
>
> Ten signals per client: repeated queries, vocabulary, structure, how often the
> model was unsure, timing. None of them depend on request volume. That's
> deliberate, because volume is the one thing an attacker can drop for free.

---

**1:27 to 1:56 - Phase 1, normal traffic**

> Two new customers. It won't judge anyone until it has thirty requests, so it
> says "collecting" for a bit.

At the green `all clean`:

> Clean. No alerts. Normal people don't trip it.

---

**1:56 to 2:18 - Phase 2, the attacker**

> Now an attacker, at the same speed as those customers, with human-looking
> timing. A rate limit would see nothing. The only difference is what it asks:
> it's probing the decision boundary, changing one word at a time to find where
> the answer flips.

---

**2:18 - The alert** (the money shot, pause a second)

> Four signals out of ten, and it says why in plain English. Near-identical
> queries, narrow vocabulary, unnaturally uniform lengths.
>
> And blocked. That key now gets a 429 on everything.

---

**2:43 - The attacker's own tally**

> From the attacker's side: sixty queries attempted, thirty-six answered,
> twenty-four refused. Caught halfway.

---

**2:44 - Results, then switch to the charts**

> At scale: twenty-five clients, twelve hundred requests. All ten attackers
> caught, one false alarm out of fifteen customers, and I'll be honest that it
> was a heavy automated account partly tripped by our own generator's odd
> sentences.
>
> The attackers include ones that slowed down, added random timing, and split
> across five API keys at a quarter request per second each. All still caught,
> because we're looking at query shape, not count.

Open `stolen_model_fidelity.png`:

> Does blocking actually save the model? Unwatched, the attacker got five
> hundred pairs and a copy that matches the victim ninety-nine percent of the
> time. Blocked at thirty queries, its copy manages eighty-seven. One error in
> eighty versus one in eight. Ten times worse.

---

**Close**

> It's all in the repo, one script runs the whole thing, and the README is
> honest about what's still weak. The core idea holds: you can't hide
> extraction by slowing down, because what gives you away is what you ask.
