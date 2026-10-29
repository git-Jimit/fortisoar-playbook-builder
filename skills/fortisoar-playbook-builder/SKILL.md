---
name: "fortisoar-playbook-builder"
description: Build, modify and review FortiSOAR playbooks as complete, importable JSON exports. Use this skill whenever the user wants a FortiSOAR playbook, workflow or automation — alert triage, incident response, investigation, IOC enrichment, phishing analysis, threat hunting, FortiSIEM or FortiAnalyzer queries, block/isolate response actions, client approval links (manual input), or PDF/HTML reports — even if they describe the logic in plain language without saying "playbook". Also use it to extend, debug, validate or review an existing FortiSOAR playbook export, to adapt a playbook for another client or tenant, or to wire sub-playbooks together.
metadata:
  version: "1.1.1"
  author: Jimit Patel
---

# FortiSOAR Playbook Builder

Turns a use case, an alert sample or an existing export into a FortiSOAR
playbook that imports cleanly **and** does useful work once it runs. Every rule
in this skill came from a playbook that failed on a real appliance — usually one
that imported without complaint and then did nothing — and each is backed by a
reference file or a validator check.

**The workflow at a glance**

| Step | What you do | Read |
|---|---|---|
| 1. Gather | Ask for what only the user can see; start building anyway | `reference/no-access-checklist.md`, `reference/connector-configs.md` |
| 2. Plan | Trigger, data source, shape, result contract | `reference/planning.md`, `reference/triggers.md` |
| 3. Verify fields | Confirm every field path exists *and* is populated | the data sample, `reference/verified-attributes.md` |
| 4. Design | Steps, branches and routes on paper | `reference/step-types.md` |
| 5. Generate | The JSON, with uuids made by code | `reference/playbook-schema.md`, `reference/conventions.md` |
| 6. Validate | Validator to 0 errors / 0 warnings, then a test matrix | `scripts/validate_playbook.py`, `reference/pitfalls.md` |
| 7. Deliver | The file, what to fill in, what was not verified | `reference/no-access-checklist.md` |

Read `reference/playbook-schema.md`, `step-types.md`, `conventions.md` and
`pitfalls.md` on **every** build — do not rely on general FortiSOAR knowledge.
Most failures of generated playbooks are already written down in `pitfalls.md`.

---

## Five principles

### 1. Assume you cannot test it

The normal case is **no appliance access**: no API, no test run, no way to look
at a record. You produce JSON; someone else imports and runs it. So:

- Get right **by construction** what you cannot test — from the reference
  files, not from memory.
- **Ask** for what only the user can see: a real `sourcedata` sample, how the
  playbook starts, connector configs, the target module and field names.
- **Say so** on delivery about anything you could not verify, and hand over a
  test plan the user can run.

Never imply something was verified when it was not. If you *do* have access,
run everything instead.

### 2. "Finished" means useful, not merely valid

A playbook that runs green and tells the analyst nothing is not finished. Match
`examples/reference-playbook-indicator-revalidation.json` — verified end to end
on a live appliance against known-correct answers:

| It does this | Not this |
|---|---|
| Classifies each indicator by type, validates it, drops noise | Passes everything straight to enrichment |
| Fans enrichment out in parallel, converges once | Chains one lookup after another |
| A verdict **per indicator**, with the reasons behind it | One overall score |
| A third bucket when sources disagree, so a human decides | Forces every case into pass/fail |
| An HTML report the analyst reads — tables, counts, the decision | A JSON blob pasted into a manual input |
| A result contract every path reaches, including the empty one | A result only the happy path produces |

Before delivering, answer three questions. If any answer is no, keep going:

1. Could an analyst act on the output **without opening the raw JSON**?
2. For any single indicator, can they see **why** it got its verdict?
3. When two sources disagree, does the playbook **say so** rather than silently
   picking one?

Depth is **proportionate**: a housekeeping count needs no enrichment or
verdicts, and padding it is its own failure. Anything that reaches a conclusion
about a threat owes the analyst its reasoning.

### 3. The delivery bar is 0 errors and 0 warnings

`scripts/validate_playbook.py` ranks findings by severity, not by whether you
may ignore them. A warning is something that will not stop the import and will
hurt at run time — a lookup loop that aborts on one bad indicator, a setting
nothing reads, a code snippet too large for the sandbox. The only accepted
exceptions are what the validator prints as **INFO** (an intentionally
unattached spare step); mention those on delivery. Anything else you knowingly
leave, name in the delivery message with the reason.

Why this strict: across independently generated playbooks, every defect that
got fixed had a validator check behind it, and every defect that survived was
documented in prose only.

### 4. Native steps first; a Code Snippet only when nothing else can do it

Every FortiSOAR upgrade can tighten the code-snippet sandbox — builtins have
been withdrawn between versions, `list` became a shim on one appliance, and a
snippet that ran last month fails the whole step with a bare 400 after an
upgrade. Native steps do not carry that risk, and analysts can read and change
them in the designer. So:

- **Do it in Jinja or a native step when you can** — field extraction and
  mapping (Set Variable), branching (Decision), switches (`when`), loops
  (connector `for_each`), record work (Find / Create / Update Record), picklists
  (`picklist` filter), building a small list (`namespace` loop).
- **Use a Code Snippet only for what Jinja does badly** — parsing raw logs or
  free text, scoring across several sources, joining fan-out results, time
  arithmetic across sources, building HTML/PDF reports.
- **Keep the ones you need few and plain**: one snippet per job, the portable
  subset in `conventions.md`, no classes or clever constructs, and a `try`
  around anything that can fail.

`conventions.md` → "Native step or Code Snippet?" has the decision table. The
validator reports the number of code snippets as INFO so the count stays visible.

### 5. Deliver a complete, importable file

- The full `{"type": "workflow_collections", "data": [...], "exported_tags": []}`
  envelope — never a fragment, pseudo-code or partial step list.
- As a real `.json` file the user can import, not a code block in chat.
- No explanation inside the JSON; explanation goes in the message.
- Complete and ready to import, unless the user explicitly asks to build in
  stages.

---

## The workflow

### Step 1 — Gather inputs, and start building anyway

Ask in your **first reply** for what you cannot derive (the exact wording is in
`reference/no-access-checklist.md`):

- **How the playbook starts** and what it runs on — analyst selection, on
  create/update, schedule, called by another playbook, or HTTP.
- **One real `sourcedata` sample** from the module it runs on.
- **A playbook export from the same FortiSOAR** containing the connectors in
  play, to harvest connector config uuids:
  `python3 scripts/extract_connector_configs.py <export.json>`. If an export is
  already in the conversation, run it on that without being asked.
- **Target module and field names**, and on a multi-tenant instance, **which
  client** the playbook is for.
- **Whether other playbooks react to alert updates** — before adding any step
  that closes an alert or writes back to a SIEM or EDR. Two playbooks writing
  back the same record overwrite each other (pitfall 41).

**Do not stall waiting.** Build in the same reply using the defaults in
`reference/connector-configs.md`, flag each one as unverified, and give the
one-line API check that confirms it. A playbook with two uuids to confirm beats
a refusal. Only a connector absent from that table genuinely blocks you — and a
**response** connector (block, isolate) on a multi-tenant instance must never
get a default, because its config selects the client's device.

**Building a playbook meant for any instance?** Use the empty config `""` on every
lookup and utility step. It means "this instance's default configuration" —
what Fortinet's own sample playbooks do — and connector versions are not
enforced, so nothing in the file is instance-specific. See
`reference/connector-configs.md`.

### Step 2 — Plan before generating

Work through all seven steps of `reference/planning.md`. The first two are hard
gates:

- **Decide the trigger** (`reference/triggers.md`). A scheduled playbook
  receives **no record**, so every `vars.input.records` reference silently
  resolves to nothing. A manual trigger cannot be driven over HTTP. An automatic
  trigger with no client condition fires for every client on the instance.
- **Establish the data source.** Print the real structure of the sample. Do not
  infer it from the use-case name: "phishing" may be a parsed email, a SIEM
  event or a gateway record, and they share no field paths. `sourcedata` may
  also be a JSON **string**, and may change shape after creation (pitfall 34).
  With no sample, say which shape you assumed and that every path is unverified.
  For email alerts read `reference/email-ingestion.md`; for FortiSIEM-ingested
  alerts, "FortiSIEM-ingested alert sourcedata" in `reference/fortisiem-queries.md`.

Then choose the **shape**:

- **Sweep** — run N checks across the estate, score, report what fired. Right
  for a scheduled hunt. See `reference/fortisiem-queries.md`, and build many
  checks as a query plan fanned out with `for_each`, not as near-duplicate steps.
- **Investigation** — a narrow trigger finds candidates, each is queried again
  in depth and written up as a case. Right whenever the user says investigate,
  triage or "what do I do about it". See `reference/investigation-pattern.md`.
  When in doubt for a malware, compromise or incident use case, choose this.

If the request is genuinely ambiguous, ask **one** clarifying question; if a
reasonable default can be inferred, proceed and state the assumption.

### Step 3 — Verify every field path

A field that exists but is never filled produces a check that returns nothing
and looks clean — this has silently disabled detections for months.

- **FortiSIEM:** grep `reference/fortisiem_event_attributes_*.csv` (both parts)
  to confirm the **name**, then `reference/verified-attributes.md` to confirm the event type
  actually **populates** it.
- **Any other source:** check the path against the real sample; for FortiAnalyzer
  use the connector's `list_log_fields` and see `reference/connector-responses.md`.
- If you cannot confirm a field, give the user a one-row query to check it, and
  say on delivery which fields were assumed.

### Step 4 — Design the flow on paper

List the steps in execution order with their types, the branches, and where the
branches converge — before writing JSON. This catches missing routes and
dangling branches early. Look up each step type's exact `arguments` shape in
`reference/step-types.md`.

Design for switches: put everything a user may tune in one Configuration step
that the playbook actually reads, and let optional steps skip themselves with
`when` so a lookup can be switched off — or deleted — without breaking the run
(pitfall 35).

### Step 5 — Generate the JSON

Follow `reference/playbook-schema.md` and the step shapes exactly. Generate every
uuid with code, never by hand. Step names use only letters, digits, underscores
and spaces — and a space in a step **name** becomes an underscore in its
**reference** (`conventions.md`). Prefer native steps (principle 4); code
snippets you do need follow the sandbox rules in `conventions.md`. For a PDF,
paste `assets/pdf_report_engine.py` — or the client's own report engine if they
already have one (`reference/reports.md`) — rather than writing a generator.

### Step 6 — Validate, then write a test matrix

```
python3 scripts/validate_playbook.py <playbook.json>
```

It catches the mechanical faults: Jinja syntax errors in any step, dangling
routes, decision conditions with no route, broken `triggerStep` and `collection` references, missing or placeholder
connector configs, step references that do not resolve, unknown step types,
sub-playbook arguments the child does not declare, banned builtins, oversized
code-snippet inputs, empty `for_each` blocks, settings nothing reads, and
malformed query conditions. Fix until **0 errors, 0 warnings**.

Two things it cannot check:

- **Code snippets.** With code execution, substitute the jinja with sample data
  and run each one; a snippet that raises fails the playbook and the sandbox
  gives no traceback. Without it, re-read each against `conventions.md` and
  confirm it ends in exactly one `print(json.dumps(...))`.
- **Generated query strings.** Read the strings the build produces, not the code
  that produces them — escaping bugs only show in the output.

**Then write a test matrix**: one scenario per scoring path with its expected
verdict, including a malformed or empty `sourcedata` case, using real known-bad
values (the EICAR hash, a documented Tor exit node) so lookups genuinely fire.
Run it if you can; otherwise ship it. Structural validation cannot catch a wrong
verdict — test matrices have found a reputation source scoring a false hit on
every known-good indicator, and a signal weighted too low to cross its own
threshold.

**Test code snippets offline before spending appliance runs.** Render each
snippet's Jinja locally with `jinja2` against a real exported alert, run the
result, and inspect its output — appliances cap playbook actions per day
(`CS-WF-38`), and a lab can hit the cap after a few dozen runs
(`no-access-checklist.md` → "If you do have access").

**No code execution?** Walk the read-only checklist in
`reference/no-access-checklist.md` against your output and give the user the
validator command to run.

### Step 7 — Deliver

Present the file, then say in plain language:

- what the playbook does, its branches and its outcomes;
- exactly what the user must fill in or confirm after import (configs,
  recipients, trigger conditions) — deliver automatically triggered playbooks
  **inactive**;
- what was **not** verified: assumed fields, first-pass thresholds, detections
  expected to be noisy, and the exact query to check each assumed field;
- the test matrix.

A first run is a calibration run. Say so rather than implying it is finished.

---

## Task-specific guidance

### Extending or modifying an existing export

- Read it with the schema in mind, not as an opaque blob.
- Keep existing step and route uuids; generate new ones only for new objects.
- Keep identity fields (`id`, `createUser`, `createDate`, `modifyUser`,
  `modifyDate`) as they are. Use `null` only on objects you create.
- Leave a mismatched `workflow.collection` alone: a single-playbook export keeps
  pointing at its home collection, and that imports fine. It is only a fault on
  a playbook built from scratch.
- Validate the **whole** playbook afterwards, not just the new part.

### Adapting a playbook for another client or tenant

On a multi-tenant instance much of the work is producing the next client's copy
of a working playbook. Four things go wrong silently:

- **Change only the playbook's own ids** — collection, workflow, step and route
  uuids and the references to them. Never `stepType`, `workflowReference`,
  connector `config`, picklist or tag IRIs. Importing the original export again
  overwrites the original. (Pitfall 36.)
- **Sub-playbook argument names differ per client.** Read the child's
  `parameters` and wire exactly those names; a misspelt argument delivers
  nothing and the child still succeeds. (Pitfall 37.)
- **The client goes in the trigger**, and the playbook ships inactive.
  (`triggers.md`.)
- **The connector config selects the client's device.** Never default a
  response connector. (`connector-configs.md`.)

Keep each copy thin: a Configuration step with everything that differs —
recipients, which indicator types this client can block, switches for
auto-block and for each lookup — and shared logic in one sub-playbook.

### Reports

For a PDF on the record and/or an emailed HTML report, follow
`reference/reports.md`: one code step builds both from the same data using
`assets/pdf_report_engine.py`, an Update Record step links the PDF to the record
(uploading alone does not — pitfall 38), and an optional connector sends the
HTML. To email the PDF itself, pass its attachment IRI in the SMTP step's
`iri_list` (`step-types.md` §15). Never put attempted credentials or secrets in
a report.

### Code snippets that read free text

Email bodies, subjects, command lines and alert descriptions break code
snippets in three quiet ways, each measured on production: the rendered input is
too big (pitfall 33), the text does not survive being pasted into the code
(inject it as `json.loads(unquote_plus("{{ x | tojson | urlencode }}"))` —
pitfall 43), and emoji make the step fail with a bare 500 when its data is
stored (scrub them — pitfall 44). Do all three for any snippet that reads text a
human wrote.

### Collections and single playbooks

The envelope is identical: a single playbook is a collection whose `workflows[]`
has one entry. Generate a single workflow unless the user wants a bundle (a
parent plus helper sub-playbooks), in which case put them in one `workflows[]`.

### Which examples to model on

- `examples/reference-playbook-indicator-revalidation.json` — **the standard.**
  Passes 0 errors, 0 warnings. Match its depth.
- `examples/sample-playbook-investigation-multiphase.json` — wiring reference for
  a multi-phase investigation. A real export: copy its wiring, not its warnings.
- `examples/sample-playbook-fortisiem-events.json` — a small complete export:
  manual trigger → branch → FortiSIEM query → result.

Model style and structure on custom, real-world playbooks like these. FortiSOAR's
bundled sample content packs are useful for discovering step types, but they are
demonstration material — do not copy their structure or naming unless the user
asks to extend one of them.

---

## Files in this skill

| File | Read it when |
|---|---|
| `reference/playbook-schema.md` | every build — envelope, collection, workflow, step and route, field by field |
| `reference/step-types.md` | every build — each step type's fixed uuid and exact `arguments` shape |
| `reference/conventions.md` | every build — naming, references, jinja filters, the code-snippet sandbox |
| `reference/pitfalls.md` | every build — the silent-failure modes and the pre-delivery checklist |
| `reference/planning.md` | step 2 — the seven planning steps |
| `reference/triggers.md` | step 2 — the five trigger types; automatic triggers on multi-tenant instances |
| `reference/no-access-checklist.md` | steps 1, 6 and 7 — what to ask, the read-only self-check, the test plan |
| `reference/connector-configs.md` | before any connector step — default config uuids and which ones vary |
| `reference/connector-responses.md` | before parsing connector output — FortiGuard, VirusTotal (IP, URL, domain, file), CrowdStrike Falcon, FortiAnalyzer, FortiDeceptor, RichTexttoPDFandEmail, artifact extraction |
| `reference/fortisiem-queries.md` | any FortiSIEM query, FortiSIEM-ingested alert `sourcedata`, and incident write-back |
| `reference/email-ingestion.md` | any phishing or email playbook — what an IMAP / Exchange email alert holds, its Source values, and Exchange connector setup |
| `reference/winrm-edl.md` | updating a firewall EDL text file on a Windows server through WinRM |
| `reference/verified-attributes.md` | before filtering or grouping on a FortiSIEM attribute |
| `reference/fortisiem_event_attributes_1.csv`, `_2.csv` | ~7,000 FortiSIEM attribute names, split alphabetically (`*`–`maxMatches`, `maxMemUtil`–`zoneName`) — grep both, do not load them |
| `reference/investigation-pattern.md` | investigate / triage use cases — detect, pivot, enrich, report |
| `reference/reports.md` | PDF or HTML output |
| `reference/changelog.md` | release notes and a summary of how the rules were measured |
| `scripts/extract_connector_configs.py` | step 1 — harvest config uuids from a supplied export |
| `scripts/validate_playbook.py` | step 6 — run on every playbook before delivering |
| `assets/pdf_report_engine.py` | paste into a code snippet to draw a PDF |
| `examples/*.json` | see "Which examples to model on" |
