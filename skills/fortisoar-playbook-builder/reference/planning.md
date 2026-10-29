# Planning — do this before writing any JSON

Most rejected playbooks are not badly coded. They are correctly coded against
the wrong assumptions. Every step below exists because skipping it produced a
playbook that imported cleanly, ran green, and was useless.

Work through all seven. Write the answers down before generating anything.

---

## 1. Decide the trigger. Ask; do not assume.

The trigger decides where input arrives, whether a record exists at all, whether
the playbook can be tested over HTTP, and how many times it runs on a multi-
record selection. Choosing it after the steps are written means rewriting every
variable reference.

Ask in these words:

> **How should this playbook start?**
> - An analyst selects records and clicks Execute
> - Automatically, when a record is created (or updated)
> - On a schedule, with no record involved
> - Called by another playbook, with parameters
> - Over HTTP, from outside FortiSOAR
>
> **And what does it run on?** One record, a batch the analyst selected, or
> nothing at all — it goes and finds its own data?

Read `triggers.md` for the five types, their confirmed input paths and the
traps. Two that decide the whole design:

- **A scheduled playbook receives no record.** `vars.input.records` does not
  exist. Every reference to it resolves to nothing, silently, and the playbook
  finishes green having done nothing. It must find its own data in its first
  real step.
- **A manual (`cybersponse.action`) trigger has no HTTP route** and can only be
  fired from the GUI. Plan the API twin now if this needs testing.

Also settle, explicitly: does it run **once per selected record**, or **once
across the whole selection**? A report per alert and a digest across alerts are
different playbooks.

When genuinely ambiguous, default to Manual on records and say so.

---

## 2. Establish the data source. Do not infer it.

**Ask for one real `sourcedata` sample from the module the playbook triggers on,
and print its actual structure.**

Do not infer the shape from the use-case name. "Phishing" can mean at least
three completely different payloads:

| Source | Where the IOCs live |
|---|---|
| Parsed email object | `headers.From`, `headers.Authentication-Results`, `body.html` |
| SIEM event | `incidentSrc.srcIpAddr`, `incidentTarget.destIpAddr`, `attackTechnique[]` |
| Mail-gateway record | vendor-specific, usually neither of the above |

They share **no field paths**. A playbook written against the wrong one extracts
nothing, scores everything CLEAN, and passes every structural check — the
validator tests wiring, not whether your field paths exist in the data.

This actually happened: a phishing playbook was built assuming a FortiSIEM event
shape, validated clean, and would have found zero indicators in every real email.

If no sample is available, say plainly in the delivery message which shape you
assumed and that **every field path is unverified**.

The same rule already applies to connector configs — *get them before
generating, not after*. Data source is the same class of problem.

## 3. Take the indicators from the raw event, not the display text

`description` and `name` are formatted for humans and usually paraphrase the
event. `sourcedata` holds what the sensor actually reported. Extract from
`sourcedata`.

Then inventory what you can actually get, by type:

- **IP** — and label each one's provenance. An address off the `Received` chain
  is a relay hop, not the sender. Listing them unlabelled misleads the analyst.
- **domain / URL** — unwrap link protection first. Microsoft Safelinks hides the
  true destination behind `safelinks.protection.outlook.com`; naive extraction
  reports outlook.com for every link. Decode the `?url=` parameter.
- **hash**
- **email address**

Filter out your own domain and well-known infrastructure (w3.org, schema.org,
microsoft.com, the recipient's own domain) before enriching — otherwise the
fan-out spends lookups on noise.

This is not only about cost. Measured on one real reported email: 59
indicators extracted, and FortiGuard returned `Decoy, ACRStealer C2` for
`microsoft.com`, `mx.microsoft.com` and `security.microsoft.com` — the mail
platform the message merely transited. Those hits then appeared in the
verdict as evidence. Drop private and reserved IP ranges too; one email
yielded `127.0.0.1` and `10.20.30.40`. See pitfalls 27 and 28.

## 4. Plan enrichment per indicator type, not per playbook

Enriching only the sender IP is the most common way a phishing playbook ends up
shallow. Every extracted type deserves a lookup:

| Bucket | Lookups |
|---|---|
| ip | VirusTotal `query_ip`, FortiGuard `threat_intel_search` |
| domain | VirusTotal `query_domain`, FortiGuard `threat_intel_search` |
| hash | FortiGuard `threat_intel_search` |

Prefer `query_domain` over `query_url` for hostnames: it costs the same one call
and additionally returns `creation_date`, which gives you a domain-age check for
free. **Domain age catches what reputation misses** — in testing, a typosquat
registered 8 days earlier came back `0/37 engines clean` on VirusTotal and was
caught only by its age.

Run the lookups **in parallel**: fan out from the analysis step, converge on the
merge step. They are independent, and a chain makes each wait on the last. A
step with several incoming routes fires once, after all branches complete —
verified, not assumed.

Read `connector-responses.md` before parsing any of these replies.

## 5. Write the scoring table before writing the code

Not "score it somehow". An explicit table, with a reason for each weight:

| Signal | Weight | Why |
|---|---|---|
| Look-alike domain | 3 | Deliberate impersonation, almost never accidental |
| Display-name brand spoof | 3 | Same |
| Domain registered < 30 days | 3 | Catches what reputation has not seen yet |
| Reputation hit (per class) | 3 | Independent confirmation |
| SPF or DMARC fail | 2 | Authentication is the strongest header signal |
| Cross-domain Reply-To | 3 | The core BEC mechanic |
| DKIM fail | 1 | Weaker alone |
| Urgency language | 1 | Very common in legitimate mail too |
| Return-Path mismatch | 1, **or 0 if SPF+DKIM+DMARC all pass** | Legitimate bulk senders do this routinely |

The conditional weights matter most. Two examples that produce false positives
if scored flat:

- **Return-Path mismatch** on a fully authenticated message is normal bulk mail.
- **Anchor text ≠ href** on a fully authenticated message is a click tracker.

Put every threshold in the Configuration step **and read it from there** —
`int("{{ vars.malicious_threshold }}")`, never a literal in the snippet. A
config value the code ignores is the most common way a "tunable" playbook
turns out not to be (pitfall 21).

State the thresholds explicitly (`>= 4 MALICIOUS`, `>= 2 SUSPICIOUS`, else
CLEAN) and put the score breakdown in the report — `header 4 + intel 3` tells an
analyst where the verdict came from; a bare number does not.

## 5b. Ask what the analyst does with this

Before the result contract, picture the person receiving it at 3am. They need to
decide something. Can they, from what this playbook produces, without opening
the raw JSON?

Concretely, for anything reaching a conclusion about a threat:

- a **per-indicator** verdict, not one score for the batch
- the **reasons** behind each verdict, in words
- what to do when sources **disagree** — a third bucket beats a coin flip
- a rendered report, not a dump

`examples/reference-playbook-indicator-revalidation.json` shows all four. Match
it. A housekeeping count does not need any of this — scale to what is being
decided.

## 6. Design the result contract

End the playbook with **one Set Variable holding everything**, placed after any
action steps so it can record what actually ran.

A later mail, ticket or export step must be able to read that one variable alone — for example `{{ vars.Result }}` when the terminal Set Variable defines `Result`. (That is a variable you define. FortiSOAR's own `vars.result` exists only inside a step's own `step_variables`; see `conventions.md`.)
If someone has to walk back through eight step outputs to build a report, the
playbook is not finished.

Minimum shape:

```
result
  meta           playbook, version, analysed_at, containment_mode
  <subject>      the thing analysed - message, host, account
  verdict        verdict, assessment, score, score breakdown, thresholds
  anomalies      [{severity, weight, detail}] - every finding WITH its reasoning
  indicators     each one WITH its enrichment and its own verdict,
                 plus counts and a flat `actionable` list
  enrichment     per-source findings
  actions        recommended / simulated / performed
  report         the rendered text
```

The `actionable` list is the one downstream steps want: only the indicators that
came back bad, ready to iterate.

## 7. Write the test matrix — run it if you can, ship it if you cannot

One scenario per scoring path, each with an **expected verdict**.

**With appliance access**, run them all and compare.

**Without access — the normal case** — you still write the matrix, and you hand
it to the user as part of the delivery so they can run it. An untested playbook
with a test plan attached is a far better deliverable than an untested playbook
with a confident summary. See `no-access-checklist.md`.

Either way the matrix is worth writing: This is not optional polish — in testing it found three real bugs
that structural validation could not:

- A reputation source scoring a false hit on every known-good indicator
- An antivirus field that was never read, so real malware scored clean
- A signal weighted too low to cross its own threshold

Cover at least: a clean authenticated message, each individual anomaly in
isolation, a known-bad indicator per enrichment class, and **malformed or empty
`sourcedata`** (it must not crash).

Use real known-bad test values so the lookup genuinely fires — the EICAR hash,
a documented Tor exit node. An invented hash returns "not found" and proves
nothing.

**When a scenario fails, decide whether the playbook or the expectation is
wrong.** Both happen. Do not bend the scoring to make a bad expectation pass.

---

## Deliver with the uncertainty stated

Say which attributes were assumed rather than confirmed, which thresholds are
first-pass guesses rather than measured, and which paths have never executed
with real data. A first run is a calibration run. Say so.
