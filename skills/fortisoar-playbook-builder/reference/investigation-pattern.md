# Investigation Pattern — when a sweep is the wrong shape

The query-plan pattern in `fortisiem-queries.md` runs N checks and reports what fired. That suits a scheduled hunt. It is the wrong shape when the user wants to *investigate* something, and the difference shows up in the output: a sweep hands an analyst a list of detections, an investigation hands them a case.

Use this pattern when the request involves words like investigate, triage, look into, what happened on, or when the deliverable should tell someone what to do about a machine rather than what fired across an estate.

---

## The architecture

```
CONFIG
  ↓
Detect_Plan        a NARROW set of high-confidence triggers
  ↓                 - not a sweep; the question is only
Run_Detect            "is there something worth examining?"
  ↓
Find_Candidates    fold hits onto the ENTITY that produced them
  ↓                 (a host, an account) and rank them
check_candidates ──no──→ end, nothing to investigate
  ↓ yes
Run_Pivot_A/B      query each candidate again with NO suspicion
  ↓                 filter - what ran, what was written, what was
Build_Cases           looked up, where it connected, what AV saw
  ↓
Reputation_Lookup  rate the indicators found
  ↓
Assess             verdict from the strongest single entity
  ↓
Build_Report       a case file per entity + a block-ready list
```

**The pivot is the point.** Once a machine is a candidate, query everything it did without any suspicion filter, then assess that activity *in the context of a machine already under suspicion*. `rundll32` is unremarkable estate-wide and notable on a host that just resolved a DGA domain. A sweep can never make that distinction because it has no context.

---

## Rules that make it work

**One query per area covering all candidates, not one per candidate.** Six areas across five hosts is 6 queries, not 30 — put the entity field in the grouping and split rows afterwards. This is the difference between two minutes and a timeout.

**Pivot windows are shorter than the detection window.** The pivot explains a trigger; it does not need a full day.

**Score the entity, not the estate.** Take the verdict from the strongest single entity. Identical detections spread across nine machines is background; the same nine on one machine is an intrusion.

**Recognise defined patterns, not just adjacency.** Execution and command-and-control are far apart in the kill chain but together describe an infection. Encryption artefacts on disk are conclusive alone. Encode those explicitly rather than relying on a generic stage-progression score.

**Trace indicators back to their origin.** A network control reports the device traffic passed through. Add a step that takes each suspicious domain and asks the DNS logs which clients queried it — that finds the machine that wanted it, which is frequently not a candidate at all. Name the top asker in the verdict even when no trigger reached it, and list askers that were never investigated so they can be carried into the next run.

**Separate confirmed from suspected in the output.** Only externally-rated indicators go on an automatic block list; behavioural findings go to a review list. Expose them as distinct step results (`BlockDomains`, `BlockIPs`, `BlockHashes`, `BlockReady`) so a blocking playbook can consume them directly.

**Only submit hashes worth rating.** A machine runs hundreds of processes; rating all of them returns a flood of signed OS binaries. Submit only hashes belonging to a file already assessed as notable.

---

## Optional patterns from real builds

These worked for one client each. Offer them; do not impose them.

**Website-access triage (FortiSIEM web-filter incident).** Parse the incident and
its `associated_events` → per site: category, firewall action, hit count →
FortiGuard (+ VirusTotal) verdict → repeat-host check (Find Records on
`alerts?$limit=200`, name `like %<src_ip>%`, `createDate gte` an ISO date —
pitfall 29) → outcome:
- *already blocked and first time* → annotate and close;
- *allowed, high-confidence malicious, auto-block on* → block and close;
- *otherwise* → an approval link with Block / Investigate Host / False Positive / Close.

**Firewall action is evidence.** Treat `block-url`, `deny`, `drop` and `reset-*`
as already blocked; anything else — including `alert`, `continue`,
`block-continue` — as allowed; an empty action as unknown, which means review,
not close. An allowlisted site counts as resolved, not as "allowed traffic", so
it does not trigger a review.

**Send clean indicators to review anyway** — some clients (e.g. for CERT-style
advisories) want every reported IP reviewed even when threat intel says clean.
Make it a Configuration switch (`ask_client_for_clean_ips`), off by default.

**Phishing analysis.** Domain age (VirusTotal `query_domain` `creation_date`:
under 30 days is a strong signal), an allowlist of known senders that downgrades
only *Suspicious* when SPF/DMARC pass and never overrides *Malicious*, and
"bulk / marketing" signs (free-mail sender promoting a company, recipients hidden
in BCC, `List-Unsubscribe`) shown as context without changing the score. Read
the email shape from `email-ingestion.md`.

---

## The report is half the deliverable

A playbook that finds the right thing and presents it badly gets ignored. What consistently gets rejected in review:

- the verdict buried under run statistics
- evidence rendered as raw `key=value` in tiny monospace
- a large "how this was found" panel dominating the actual finding
- no statement at all when nothing was found

### Structure that works

1. **Verdict + why**, naming the entity. First thing on the page.
2. **"What was found"** in plain language — *N detections, on which machines* — or an explicit green statement that nothing was found and how many checks ran.
3. **A case file per entity**: why it surfaced, what its wider activity looked like, accounts involved.
4. **Each finding as labelled facts**, headed by the most identifying value:

   > **HOW_TO_DECRYPT.txt**
   > File — HOW_TO_DECRYPT.txt
   > Location — d:\shares\finance\ledgers
   > Account — admin.kd
   > Times seen — 38

   Translate attribute names to labels: `procName` → Process, `DNSQNAME` → Domain queried, `serviceFileName` → Service binary.

5. **Three verification lines on every finding:**

   | | |
   |---|---|
   | **HOW TO VERIFY** | the specific check to run |
   | **LEGITIMATE IF** | what a benign explanation looks like |
   | **CONFIRMED IF** | what would settle it as malicious |

   The middle line matters most. It is what lets an analyst close something, and it is what stops the report becoming a backlog.

6. **The query that produced it** — small, muted, at the bottom. Present so the finding can be reproduced, not competing with it.
7. **Block-ready indicators**, separated from those held for review.
8. **What was checked and what could not be** — every trigger with its result, and the coverage gaps.

### Report honesty rules

- A failed query is reported as **not run**, never as clean.
- An unrated indicator is **unrated**, never safe — infrastructure registered for a live campaign has no record yet.
- A lookup that returned nothing is **no response**, distinct from a negative verdict, and flagged at the top.
- A capped query window is stated on the finding, so a quiet result is not read as a full-window clean.

---

## The first run is a calibration run

Never present a freshly generated detection playbook as finished. Every one of these needed 4–6 tuning rounds against live data before it was usable. Say so at delivery, and plan the loop:

1. **Run it.** Expect noise.
2. **Look at what fired and identify the source.** Almost every false positive is identifiable software — a backup agent, a monitoring platform, an updater, a corporate screensaver.
3. **Fix the cause, not the symptom.** Raising a threshold hides a bad query; narrowing the match fixes it. Matching `vssadmin` fired on `vssadmin list shadows` from every backup agent — the fix was matching `delete shadows`, not a higher threshold.
4. **Exclude by exact value at query time**, and record the evidence in a `note` on the detection.
5. **Repeat until a normal day is quiet.**

Track the score across rounds and report it — *102 → 87 → 57 → 38* is a legible sign of progress and sets the expectation that this is a process.

**A detection that returns zero on the first run has not been validated.** It may be correct, or it may be dead. Confirm by removing filters until something comes back — if the broadest form returns nothing, it is a genuine coverage gap; if it returns rows, a filter is wrong.
