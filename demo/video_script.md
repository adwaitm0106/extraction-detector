# Video script

Read this while the demo runs. Times are from the moment you press Enter on
`run_demo.ps1`. They match a warm run on the development laptop; if your
machine is slower the phases stretch but the order never changes, so follow the
banners on screen rather than the clock.

Before recording: run the demo once so the model weights are cached, close
other terminals, make the font big, and have the two charts from
`eval/figures/` open in a second window for the end.

Total speaking time is about five minutes.

---

## 0. Before you press Enter (about 30 seconds)

**Screen:** empty PowerShell in the `extraction-detector` folder, the command
typed but not run.

> If you sell access to a machine learning model through an API, there's a way
> to steal it that doesn't involve breaking anything. You just use it. You send
> it inputs, save the answers, and train your own model on those pairs. At the
> end you've got a working copy, and the victim's logs show nothing but a
> customer using the product.
>
> The usual defence is a rate limit. That stops people in a hurry. It does
> nothing to someone patient. One query a second looks like a normal customer,
> and in a week that's plenty of data.
>
> So we built something that doesn't look at how much you ask. It looks at what
> you ask. And when it's sure, it cuts you off. Let me show you.

Press Enter.

---

## 1. Startup, 0:00 to 0:15

**Screen:** purple banner `EXTRACTION DETECTOR - LIVE DEMO`, then
`> starting the victim API`, then `API ready: model_loaded=true`.

> That's the victim. It's a sentiment classifier, DistilBERT, running on CPU.
> It answers with a label and a confidence, and it writes one line to a log
> file for every request: who asked, what they asked, what it answered.
> Everything the detector does, it does from that log.

---

## 2. Calibration, 0:15 to 1:26

**Screen:** yellow banner `CALIBRATION: learning what normal looks like`. Then
about 70 seconds of nothing visible while four fake customers run. Then
`> fitting the baseline` and `calibrated on 8 benign windows from 4 clients`.

This is the longest quiet stretch. Use it to explain the design.

> Right now four ordinary customers are querying the API. The detector is
> watching them to learn what normal looks like. Normal vocabulary, normal
> amount of repetition, normal timing.
>
> The important thing is what it's *not* seeing. It's not seeing any attacks.
> We never show the detector an attack while it's learning. That matters,
> because the easy way to get a good-looking result in this kind of project is
> to tune the detector on the same attacks you then test it against. We didn't
> do that. It learns "normal" and nothing else, and later it flags whatever is
> far from normal.
>
> It measures ten things per client. How often queries repeat or nearly
> repeat. How rich the vocabulary is. How much the queries share one structure.
> How often the model was unsure of its answer. How bursty the timing is. None
> of those ten depend on how many requests you send. That's on purpose. Volume
> is the obvious signal and it's the one an attacker can drop for free.
>
> For each of those ten it learns a middle and a spread. That's it. Twenty
> numbers. There's no model to overfit.

When `fitting the baseline` appears:

> There's the baseline. From here on, anything more than three and a half
> standard deviations from normal on at least two of those ten signals gets
> flagged. Both of those numbers were fixed up front, before we saw any
> results.

---

## 3. Phase 1, normal traffic, 1:27 to 1:56

**Screen:** green banner `PHASE 1: Normal traffic - watch the console`. Grey
lines counting up: `9 requests seen - collecting (need 30 per client before
scoring)`, then eventually `30 requests scored - all clean` in green.

> Two new customers now. Different people from the ones it calibrated on. The
> detector is scoring live every three seconds.
>
> You'll notice it says "collecting" for a while. It won't judge anyone until
> it has thirty requests from them. We learned that one the hard way. If you
> score a half-filled window against a baseline built on full windows, the
> timing features go haywire and you flag innocent people. So it waits.

When the green `all clean` lines appear:

> And there we go. Thirty requests scored, all clean. No alerts. That's the
> whole point of this phase. Normal people don't trip it.

**Screen:** `Phase 1 over: no alerts, as expected.`

---

## 4. Phase 2, the attacker, 1:56 to 2:19

**Screen:** red banner `PHASE 2: Attacker starts now`, the explanation text,
then more grey collecting lines, then two more `all clean` lines.

> Now the attacker. And here's the thing: it's running at the same speed as
> the customers you just saw. About one and a half requests a second. Its
> timing is randomised the way a real person's would be. If you were looking
> at request counts, or a rate limit, you would see nothing.
>
> The only difference is what it's asking. It's probing right around the
> model's decision boundary, taking a sentence and changing one word at a time
> to find exactly where the answer flips. That's how you map a model.
>
> It needs thirty requests before it can be scored, same as everyone else, so
> there's a short wait here.

Keep talking calmly through the two `all clean` lines. Those are the
customers, still clean. The attacker isn't scorable yet.

---

## 5. The alert and the block, 2:19

**Screen:** red `[ALERT] EXTRACTION SUSPECTED api_key=extraction-attacker
flags=4/10`, a `signals:` line, a `why:` line, then yellow `[BLOCK]
api_key=extraction-attacker now gets HTTP 429 on every request`.

Pause for a second so the viewer can read it, then:

> There it is. Flagged on four out of ten signals, and the detector says why
> in plain words: it's sending near-identical queries, using a narrow
> vocabulary, its query lengths are unnaturally uniform.
>
> That "why" line matters more than it looks. If you wrongly flag a paying
> customer, that's a support ticket and maybe a lost account. So the detector
> never just says "attacker". It shows its reasoning, and it won't flag anyone
> on a single signal.
>
> And then the yellow line. The key's been blocked. The API is now answering
> every request from it with a 429. The attacker's harvest just stopped.

---

## 6. The attacker's own tally, 2:42

**Screen:** `What the attacker saw from its side:` then `sent 60 requests` and
`status codes: {200: 37, 429: 23}`.

> This is from the attacker's point of view. It tried to send sixty queries.
> Thirty-seven got answers. Twenty-three got a 429 and nothing else. It got
> caught a little over halfway through, and everything after that was wasted.

---

## 7. Results table, 2:42 to 2:43

**Screen:** the scoring table, `1 of 3 clients flagged`, the `blocked.json`
contents, the confusion matrix with `precision 1.000 recall 1.000`.

> The final table. Attacker flagged, both customers clean, and there's the
> blocklist file the API is enforcing from. Then the script shuts everything
> down and clears the block, so nobody stays throttled after a demo.

---

## 8. Switch to the charts (about 90 seconds)

**Screen:** open `eval/figures/flags_per_client.png`.

> That was three clients. We also ran it at scale: twenty-five clients, fifteen
> normal and ten attackers, twelve hundred requests. Every red bar is an
> attacker, every green bar is a normal customer, and the dashed line is the
> threshold.
>
> All ten attackers were caught. One normal customer was flagged, and that's
> worth being honest about. It was a heavy automated integration, ninety
> requests, and two of its queries in one window came out with the model
> unsure, partly because our own fake customer generator had produced a couple
> of self-contradicting sentences. So the real false-alarm rate is something we
> don't fully know yet. What we can say is one in fifteen on traffic that was
> deliberately varied.
>
> And the attackers include the hard ones. One slowed down to human speed. One
> added random timing. One spaced its requests like a real person. One split
> the work across five separate API keys, a quarter of a request per second
> each, which beats any rate limit you would realistically set. All five of
> those keys were still caught individually, because the detector is looking at
> the shape of the queries and not the count.

**Screen:** open `eval/figures/stolen_model_fidelity.png`.

> Last thing. Does blocking actually protect the model, or does it just make a
> nice alert? We tested it by playing the attacker properly. We harvested
> question and answer pairs from the victim and trained a copy on them, then
> measured how often the copy agrees with the original on sentences neither had
> seen.
>
> The red line is the attacker with nobody watching. The more it harvests, the
> better its copy gets, up to five hundred pairs and a copy that agrees with
> the victim ninety-nine percent of the time. Wrong about one time in eighty.
>
> The green square is the same attacker with the detector enforcing. It got
> cut off after thirty queries. Thirty is the earliest the detector can act
> at all. The copy it was left with agrees eighty-seven percent of the time.
> Wrong about one time in eight.
>
> One in eighty versus one in eight. Ten times the error rate. And I'll be
> straight that the test sentences come from the same template family as the
> attacker's queries, so eighty-seven is generous to the attacker. On real
> text, thirty pairs would buy them a lot less.
>
> That's the difference the detector makes, measured in the attacker's own
> currency.

---

## 9. Close (about 20 seconds)

**Screen:** back to the terminal, or the README.

> Everything you saw is in the repo. One script runs the whole demo. The
> README has the numbers, the charts, and a long section on what's not good
> enough yet, because most of this is a first version and the fake traffic is
> still fake. But the core idea holds up: you can't hide extraction by slowing
> down, because the thing that gives you away isn't how much you ask. It's
> what you ask.
>
> Thanks.
