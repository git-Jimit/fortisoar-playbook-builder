# Building blind — the normal case

**Assume you cannot reach the appliance.** No API, no test run, no way to see a
record. You are producing JSON from knowledge, and someone else imports and runs
it. Everything in this skill is written for that.

That changes three things:

1. What you cannot test, you must get right **by construction** — from the
   reference files, not from memory of FortiSOAR in general.
2. What only the user can see, you must **ask for**. A question costs one
   message. A wrong guess costs them a debugging session.
3. What you could not verify, you must **say plainly** on delivery, and hand
   over the means to check it.

Never imply something was verified when it was not. "This will work" is a claim
you have not earned. "This is correct against the documented shapes; these three
things need checking on your instance" is honest and far more useful.

---

## Ask for these — you cannot derive them

Ask in the **first reply**, together, not one at a time:

1. **One real `sourcedata` sample** from the module this triggers on. Paste of
   the raw JSON. Without it you are guessing field paths, and a playbook built
   against the wrong shape extracts nothing while passing every check.
2. **Connector config uuids and versions.** Ask for an export — but do not
   wait for one. `connector-configs.md` carries uuids observed on more than one
   instance (AbuseIPDB and FortiGuard are stable; VirusTotal demonstrably is
   not). Build with those, list them under *unverified*, and give the user the
   one-line check. Versions vary more than uuids do, so ask for the version even
   when you are confident of the uuid.
3. **How it starts** — see `triggers.md`. Manual, on create, scheduled,
   referenced, or API.
4. **The module and any custom field names** it writes to.
5. **Other playbooks that react to alert updates** — only when this playbook
   closes alerts or writes back to a SIEM / EDR. Ask what they trigger on and
   what they write back (pitfall 41).

If the user cannot supply an item, proceed with a stated assumption rather than
stalling — but list it in the delivery message under *unverified*.

## Self-check by reading

The validator script only helps if you can execute code. When you cannot, walk
this list against your own output before delivering. Every item is a real
failure that reached a working playbook.

**Wiring**
- [ ] Every step's uuid appears as a route `sourceStep`, unless it is a terminal
      step
- [ ] Every Decision `conditions[].step_iri` has a matching route with the same
      source and target
- [ ] `triggerStep` names the actual Start step's uuid
- [ ] The Workflow's `collection` matches the parent WorkflowCollection uuid
      (on a playbook you generated — not on an uploaded export)
- [ ] Every uuid is a real uuid4, generated not hand-typed, and unique across
      steps, routes, groups and the workflow itself

**Naming**
- [ ] Step and variable names contain only word characters and spaces. A hyphen
      breaks the Jinja reference — `SIMULATED - Block IP` cannot be read as
      `vars.steps.SIMULATED___Block_IP`
- [ ] **Every `vars.steps.` reference uses underscores where the step name has
      spaces.** `Get Oldest Blocked IPs` is referenced as
      `vars.steps.Get_Oldest_Blocked_IPs`. A reference carrying literal spaces
      resolves to nothing silently — no error, no enrichment, a green run. Grep
      the finished file for `vars.steps.` and check every hit against the step
      list

**Variable references**
- [ ] Code Snippet output read as `vars.steps.<Name>.data['code_output']`
- [ ] Plain connector step read as `vars.steps.<Name>.data.<field>` — the step
      result IS the envelope `{"data": {...}, "status": "Success", ...}`, so the
      payload sits under `.data`. Verified against three connectors (AbuseIPDB,
      FortiGuard, VirusTotal) on a live appliance. An earlier version of this
      checklist said "no `.data`" for connector steps — that was wrong, and a
      playbook following it resolves to nothing, silently
- [ ] `for_each` connector step read as `vars.steps.<Name>` — that name is a
      **list** of those same envelopes, so `.data` on the list itself is
      undefined; iterate and read `e.data.<field>` per entry
- [ ] Find Records read as `vars.steps.<Name>` — the list itself, **never**
      `.data`. A `| default([])` beside a wrong `.data` turns the mistake
      into a silent empty batch and a green run (pitfall 24)
- [ ] `query.limit` is an integer literal, not a jinja string — a string is
      ignored and the fetch silently returns the 30-record ceiling
- [ ] Filters on date fields use ISO strings (`"2026-08-01"`), never epochs —
      a number returns a DriverException 400. End bounds use `lt <next day>`,
      because a bare date means midnight (pitfall 29)
- [ ] No step carries a `for_each` block with an empty `item`. An empty
      stub is runtime-fatal (CS-WF-3), not a no-op — delete the key on
      steps that do not loop
- [ ] Results of a `for_each` with `parallel: true` are joined on a value
      the response echoes back, never by positional index — parallel
      results return in completion order and silently attach to the
      wrong item (pitfall 23)
- [ ] Input path matches the trigger: `records[0]` for manual/on-create,
      `params['<name>']` for referenced, `params.api_body.<name>` for API, and
      **no records at all** for scheduled
- [ ] `vars.result` appears only inside a connector step's own `step_variables` — elsewhere it does not resolve
- [ ] No code snippet renders a whole record or `sourcedata`; the jinja builds a trimmed dict (a 2.3 MB alert failed with a bare 500)
- [ ] `sourcedata` handled as either a dict or a JSON string (`is mapping` else `| toDict`)
- [ ] Every reference to a step that can be skipped, switched off or deleted is wrapped in `| default({}, true)`
- [ ] Code avoids bare `isinstance(x, list)` — use `LIST_T = builtins.list` or a dict-first branch
- [ ] Every Reference-a-Playbook argument name matches the child playbook's declared `parameters`
- [ ] If the playbook was copied: only its own ids changed; `stepType`, `workflowReference`, configs and picklists untouched; no stale `message.parentstepid`
- [ ] A generated report is linked to the record with an Update Record `attachments` Append, not only uploaded
- [ ] A step that several branches converge on references only steps that run on
      *every* one of those branches

**Code snippets**
- [ ] Every Code Snippet step carries the full connector envelope —
      `connector: "code-snippet"`, `operation: "python_inline_code_editor"`,
      `version`, and a real `config`. `params.python_function` alone is a dead
      step
- [ ] No call to `set`, `any`, `all`, `enumerate`, `sum`, `max`, `min`, `type`,
      `eval`, `exec`, `map`, `filter`, `open`, `reversed`. `sorted`, `zip`,
      `abs` and `round` ARE allowed. The check is on the call only — the same
      words in comments, strings or identifiers are fine
- [ ] Every Find Records step that needs more than 30 rows carries `$limit`
      in its **module string** — `query.limit` alone returns 30 (pitfall 31)
- [ ] Any "examined X of Y" claim gets Y from something other than
      `len(rows)`, or says the population is unknown (pitfall 32)
- [ ] `true, false, null = True, False, None` aliased at the top if any JSON is
      injected
- [ ] Every key the code brackets out of an injected structure is a key the
      jinja loop actually builds — and prefer `.get(k, default)` to `[k]`,
      because a missing key is a KeyError that kills the step (pitfall 30)
- [ ] Exactly one `print()`, last line, of `json.dumps(...)`
- [ ] No whole connector payload injected — pull out the small fields with a
      Jinja loop, or a VirusTotal whois blob will break the source

**Substance**
- [ ] Every Configuration/Set Variable key is actually READ somewhere
      (`vars.<key>`). A config step nothing reads makes the playbook look
      tunable when it is not — and check the code does not hardcode the same
      value alongside it
- [ ] Private, loopback, link-local and documentation IP ranges are dropped
      before enrichment, along with your own domain and the mail platform's
      own domains. Enriching them manufactures false positives (pitfall 27)
- [ ] Extracted URLs and domains contain no whitespace, backslash or control
      character - an unanchored regex swallows the next line (pitfall 28)
- [ ] Every extracted indicator type is enriched, not just the first one
- [ ] Threat-intel replies parsed **by field**, never by substring on the
      serialised response
- [ ] Weights that fire on legitimate mail are conditional (see `planning.md`)
- [ ] One Set Variable at the end holding the whole result

## Trace each requirement, do not assert it

Before delivering, take every requirement the user stated and follow it through
the actual JSON, concretely. Not "the threshold is configurable" — instead:

> The user opens the Configuration step, changes the threshold from 10 to 50,
> saves, re-runs. Which step reads that value? What does it compare? Which
> indicators change bucket?

If you cannot name the step that reads the value, the requirement is not met.

This is not a formality. Asked exactly that question about a playbook it had
just declared complete and validated, an AI found within seconds that its own
scoring step hardcoded `threshold = 10` while the Configuration step it had
built held the number nobody read — and correctly told the user not to import
it. The bug had survived generation, self-review and a clean validator run,
because nothing had walked the requirement end to end.

Do this for every requirement: the batch cap, the indicator types, the buttons,
the dummy steps, the single result variable. One pass, concrete, naming steps.

## Ship a test plan, not a promise

You cannot run the scenarios. Write them out so the user can, and give each an
expected verdict. Put it in the delivery message or a short block they can keep:

```
S1  fully authenticated, no anomalies        -> CLEAN
S2  look-alike sender domain                 -> MALICIOUS
S3  SPF and DMARC fail                       -> MALICIOUS
S4  display name claims a brand              -> MALICIOUS
S5  Reply-To on another domain               -> MALICIOUS
S6  known-bad hash (EICAR)                   -> MALICIOUS
S7  brand subject, no auth headers           -> SUSPICIOUS
S8  known-bad sending IP (Tor exit)          -> MALICIOUS
S9  anchor text != href, unauthenticated     -> MALICIOUS
S10 empty / malformed sourcedata             -> CLEAN, must not error
```

Tell them to use **real known-bad values** — the EICAR hash, a documented Tor
exit node. An invented hash returns "not found", the path looks fine and nothing
is proven.

And tell them what to do when one fails: decide whether the playbook or the
expectation is wrong. Both happen.

## State the uncertainty on delivery

Close every delivery with this, filled in honestly:

- **Assumed, not verified:** field paths, attribute names, anything derived from
  a sample rather than seen on their instance
- **Needs filling in post-import:** connector configs, picklist uuids,
  sub-playbook references
- **First-pass guesses:** every threshold and weight. A first run is a
  calibration run
- **Never executed:** any branch that no supplied sample would reach — commonly
  the hash path when no sample had an attachment

## If you *do* have access

Then run things: execute each code snippet with representative input, run the
validator, import and drive the playbook through the matrix, and read the step
outputs. `planning.md` step 7 assumes this. It is the exception, not the rule —
and everything above still applies to whatever you could not reach.

**Spend appliance runs carefully.** Appliances cap playbook actions per day; a
lab stopped every run with `CS-WF-38: Daily limit for action count has been
exceeded` after a few dozen test runs of a 15-step playbook. Before importing:

- render each code snippet locally — load the exported workflow, render the
  snippet's `python_function` with `jinja2` against a real exported alert
  (`vars.input.records[0]`, `vars.steps.<Name>` stubbed with captured outputs)
  and run it; this finds most errors without a single appliance action;
- when a read-only query is allowed, feed the snippet live query results the
  same way, so the logic is tested against real data;
- on the appliance, run one case per branch, not every sample.

**Never let a test touch production systems through the lab.** A lab's
connectors may point at production (a SIEM, an ITSM). Switch off, in the test
copy, every step that is not a read-only query — including sub-playbooks that
call other connector actions — and give test records an obvious `TEST - ` name.
