# Pitfalls — how a playbook silently does nothing

Every entry here is a real failure. What they share is that the playbook **imported cleanly, ran without error, and produced a plausible result** while being wrong. These are more dangerous than a crash, because nobody investigates a green run.

Work through this list before delivering.

## Contents

Numbers are stable — other files refer to pitfalls by number. The
**pre-delivery checklist** is at the end.

**Detection quality and verdicts**
- 1. Zero results is a claim that needs evidence
- 2. A valid attribute name is not a populated one
- 3. Thresholds must come from measured volume
- 4. Match intent, not keyword
- 5. Exclusions belong at query time, and by exact value
- 6. Counting is not correlating
- 7. A control names the machine that forwarded, not the one that acted
- 8. Absence of a threat-intel record is not a clean result
- 9. Do not auto-block on behaviour
- 10. Report the finding, not the mechanism
- 14. Threat-intel hits must be read by field, never by substring
- 15. Absence of authentication evidence is not a clean result
- 27. Enriching your own infrastructure manufactures false positives

**Reading the input data**
- 26. A nested object field renders as the string Array
- 28. Strip control characters when extracting from a body
- 33. A code snippet that renders the whole record fails with a bare 500
- 34. sourcedata is often a string, and a string has no fields
- 39. An undefined value passes `is sequence` and `is iterable`
- 43. urlencode turns spaces into `+` — decode with unquote_plus
- 44. Emoji in a code snippet's data make the step fail with a bare 500

**Wiring, references and copying**
- 11. Cloning a step keeps the original's references
- 12. Routing must test the same value the verdict uses
- 13. A shared terminal step cannot read a branch-local variable
- 21. A Configuration step nothing reads is worse than none
- 24. Find Records has no .data, and default([]) hides it
- 30. The jinja loop and the code reading it drift apart
- 35. A skipped step makes its own reference an error
- 36. Copying a playbook: change only its OWN ids
- 37. Sub-playbook argument names differ between clients

**Response and write-back**
- 41. Two playbooks writing back the same alert or SIEM incident overwrite each other
- 42. A placeholder response step must not record an outcome

**Loops and fan-out**
- 22. An empty for_each block kills the step
- 23. Parallel for_each results are not in input order
- 40. sorted() on tuples crashes when two first values are equal

**Queries, limits and dates**
- 17. isnotnull breaks if the filter carries a value key
- 18. The fetch window must be wider than the batch cap
- 25. A jinja string in query.limit is silently ignored
- 29. Date filters take ISO strings, not epochs — and a bare date means midnight
- 31. query.limit on a Find Records step does nothing
- 32. "Examined 30 of 30" when there are 550

**Testing and the platform API**
- 16. A test scenario must use a real known-bad value
- 19. Creating a playbook by POSTing a collection leaves the trigger dead
- 20. A manual input cannot be resolved over the API

**Output**
- 38. Uploading a file is not attaching it to the record

---

## 1. Zero results is a claim that needs evidence

A detection returning nothing means one of three things, and they are not interchangeable:

- the activity genuinely did not occur
- the query is broken
- the data needed to see it is not collected

**Never let the third and second read as the first.** Cases where a detection was dead and looked clean:

| Detection | Wrote | Should have been | Result |
|---|---|---|---|
| Admin-share access | `osObjName CONTAIN "ADMIN$"` | share name is in `fileName` on that event | 4 events in 7 days, looked quiet, was blind |
| Execution from Temp | `procName CONTAIN "\\AppData\\Local\\Temp\\"` | single backslashes, no trailing one | 0 rows, looked clean, matched nothing |
| Process activity by IP | `hostName CONTAIN "10.20.30.41"` | machine's own address is in `reptDevIpAddr` | 0 rows on every host |

**Check:** when a detection returns nothing, run the same query with the filters progressively removed until something comes back. If removing a filter produces rows, the filter is the problem. If the broadest form returns nothing, the source genuinely has no data — record that as a coverage gap.

---

## 2. A valid attribute name is not a populated one

An attribute can exist in the schema, be accepted by the query, and never be filled in by the parser for that event type. Grouping on it returns blanks; filtering on it matches nothing.

Confirmed examples on one instance:

| Event type | Does **not** populate | Does populate |
|---|---|---|
| `Win-Security-4697` | `osObjName` | `serviceName`, `serviceFileName`, `serviceAccount` |
| `Win-Security-4670` | `osObjName` | `procName`, `osObjType` |
| `Win-Security-5140` | `osObjName` | `fileName`, `filePath`, `srcIpAddr` |
| `Win-Security-4698` | `taskName` | `user`, `hostName`, `eventAction` |
| `Trellix-domain-match` | `hostName` | `srcName`, `cncName`, `signatureName` |
| `PH_OSQUERY_WIN_POWERSHELL_BAD_PARENT` | `procName`, `parentProcName`, `user` | — detail is unparsed |

**Check:** before using an attribute, ask the user to run one query displaying it, over 7 days, and confirm it comes back populated. The attributes CSV proves a name is valid, not that it is filled in.

**A blank column in a result is a finding, not cosmetic.** In one case the security query grouped on `hostName` (blank) and never requested `signatureName` — so `Backdoor.SUNBURST.DNS` was reported as "an endpoint protection event".

---

## 3. Thresholds must come from measured volume

A threshold picked from intuition is either unreachable or fires constantly.

- `Win-Security-5140` had 4 events in 7 days; the threshold was 5. It could never fire.
- `Win-Security-4624` was assumed at 14.8M/7d from a stale comment; actual was 17,456. The threshold was 300× too high.

**Check:** ask for a volume query before setting a number.

```
<the detection's cond> AND (customer = "<Org>")
```
group by the entity, display `COUNT(*)`, top 30 descending, 7 days.

Set the threshold from the observed distribution, and record the measurement in a `note` on the detection so the next person knows where the number came from.

---

## 4. Match intent, not keyword

Most first-draft detections fire on the benign majority of a pattern.

| Fired on | Actually was | Fix |
|---|---|---|
| `command CONTAIN "vssadmin"` | `vssadmin list shadows` — read-only, every backup agent | match `delete shadows`, `resize shadowstorage` |
| `command CONTAIN "netsh advfirewall"` | `netsh advfirewall export` — backup software | match `advfirewall set` |
| `fileName CONTAIN "RESTORE"` | `adsrestoredbaudit.txt` — a backup product | match full ransom-note names |
| `command CONTAIN "bypass"` | `-ExecutionPolicy Bypass` — monitoring agent, 3,012 hits | match encoding and download markers |
| `.pdf.` double extension | `photo.jpg.~tmp` — Windows Camera | exclude `~tmp`, `crdownload`, `zone.identifier` |

**Check:** for each detection, name the most likely benign source of the same pattern in a bank or enterprise estate. If you cannot rule it out in the query, expect a tuning round and say so on delivery.

---

## 5. Exclusions belong at query time, and by exact value

Known-good automation is best removed in the `cond` so it never reaches scoring. Use exact matches where the value is exact — `filePath != "c:\screensaver"` rather than `NOT CONTAIN "screensaver"`, which would also exclude an attacker's folder that happens to contain the word.

Record the evidence in the detection's `note`: *"the first live run returned 130 rows and every one was OneDrive or the ARCON client."*

---

## 6. Counting is not correlating

Summing weights across an estate answers "did anything fire anywhere", which is not a question worth alerting on. Twenty detections across five thousand machines is background. Four on one machine is an intrusion.

**Group findings by the entity that produced them** — a host, an account — and score each entity on its own. Take the verdict from the strongest single entity, never from an estate total.

Tested on identical inputs:

| Same 9 detections | Estate score | Best entity | Correct verdict |
|---|---|---|---|
| all on one host | 47 | 47 | attack |
| spread over nine hosts | 48 | 10 | background |

---

## 7. A control names the machine that forwarded, not the one that acted

Network security controls report the device the traffic passed through. On a DNS server that is every client behind it, so an investigation points at the resolver and the infected machine never surfaces.

One instance: two domain controllers showed thousands of malware callbacks each. Tracing the C2 domain back through DNS query logs found three clients, one of them querying 4,022 times — and it had never been a candidate.

**Check:** when a finding is attributed to infrastructure, add a step that traces the indicator back through the logs that record the originating client, and name the machine that appears most.

Related: on those events the destination address is the upstream resolver, not the attacker. Take the indicator from the field naming the C2 host (`cncName`), never from `destIpAddr`.

---

## 8. Absence of a threat-intel record is not a clean result

"Information not found" means unrated. Infrastructure registered for a live campaign has no record yet — precisely the case the playbook exists to catch.

Also distinguish **no response** from **not rated**. If the lookup fails and returns nothing, the code must not treat it the same as a negative verdict. Count them separately, and if any lookup did not return, say so at the top of the report:

> *N of M lookups returned nothing. Those indicators have not been checked. Do not read the absence of a malicious rating as a clean result.*

---

## 9. Do not auto-block on behaviour

Only indicators with an external malicious rating belong on an automatic block list. Behavioural findings go to a separate review list for an analyst to confirm.

Also: never propose blocking an address that belongs to the customer's own ranges or to their upstream resolver. Both have appeared in generated block lists — blocking the resolver would break name resolution estate-wide.

---

## 10. Report the finding, not the mechanism

Common in generated reports: a large panel headed "how this was found" with the query, and the actual evidence in 9px monospace `key=value` underneath.

Invert it. The finding leads:

> **HOW_TO_DECRYPT.txt**
> File — HOW_TO_DECRYPT.txt
> Location — d:\shares\finance\ledgers
> Account — admin.kd
> Times seen — 38

Translate attribute names to labels (`procName` → Process, `DNSQNAME` → Domain queried). Keep the query, small and at the bottom, so the finding can be reproduced.

**Give every finding three lines an analyst can act on:** what to check, what would make it legitimate, and what would confirm it. The middle one matters most — it is what lets someone close a finding, and it is what stops the report becoming a backlog.

---

## 11. Cloning a step keeps the original's references

Cloned steps carry the original's name inside their own `step_variables` expression, so the clone reads the wrong step's output. A clone also keeps the original's `for_each.item`, `operation` and `version`.

**Check:** after cloning, confirm the clone's `step_variables` references its own name.

---

## 12. Routing must test the same value the verdict uses

One playbook computed its verdict from a correlated per-entity score but routed on the old estate-wide total. Correlation dismissed the run; the routing alerted anyway.

**Check:** the expression in a Decision step names the same field the verdict logic produced.

---

## 13. A shared terminal step cannot read a branch-local variable

Two branches converging on one Update Record step, where the expression names a
step that only runs on one of them, writes an **empty string** on the other
path. The playbook reports success and the record is annotated with nothing.

`| default(...)` does not rescue it: the whole reference chain is undefined, not
just the leaf, so the default never applies.

**Check:** every expression in a converging step must name only steps that run
on *every* incoming branch. If it cannot, give each branch its own writer.

---

## 14. Threat-intel hits must be read by field, never by substring

Lower-casing a connector reply and searching for `"malicious"`, `"spam"` or
`"phishing"` matches the response schema's own **field names**. FortiGuard
returns a key called `spam_cates` on every reply, so every indicator it
recognises scores a hit — including known-good infrastructure.

Measured: a clean Google DNS lookup produced a full malicious hit, and a clean
authenticated email graded SUSPICIOUS. In production this grades nearly
everything suspicious.

**Check:** extract the specific fields and test them individually. See
`connector-responses.md` for the confirmed shapes and which field carries an
antivirus detection (`av_cate`, not `malware_name`).

---

## 15. Absence of authentication evidence is not a clean result

A message with no `Authentication-Results` header at all is not the same as one
that passed. If the message also impersonates a brand, absence of proof is a
finding, not a pass — it is the exact template attackers clone.

Conversely, two signals must be *downgraded* when authentication fully passes,
or they generate constant false positives on legitimate bulk mail:

- Return-Path differing from From — routine for ESP-sent mail
- Anchor text differing from its href — routine click tracking

**Check:** for every header signal, ask what a legitimate bulk sender does. If
the answer is "the same thing", the weight must be conditional on
authentication.

---

## 16. A test scenario must use a real known-bad value

An invented hash or a made-up domain returns "not found", the enrichment path
appears to work, and nothing is proven. Use documented known-bad values — the
EICAR test-file hash, a published Tor exit node — so the lookup genuinely fires.

**Check:** if a test scenario passes with zero enrichment findings, confirm the
lookup actually ran rather than assuming the path is covered.

---

## 17. `isnotnull` breaks if the filter carries a `value` key

A Find Records filter using `isnotnull` (or `isnull`) must omit `value`
entirely. Leaving it in — even as `""` or `null` — returns HTTP 400 wrapping a
500, with only *"Internal Server Error. Check log 'prod.log'"* to go on. The
step fails and the whole playbook stops on its third step.

```json
{"type": "primitive", "field": "idicator",
 "operator": "isnotnull", "_operator": "isnotnull"}
```

No `"value"` key. Every other operator (`eq`, `neq`, `like`) requires one, so
this is easy to get wrong by copying a neighbouring filter.

**Check:** grep the generated query for `isnotnull` and confirm no `value` sits
beside it.

---

## 18. The fetch window must be wider than the batch cap

If Find Records fetches exactly as many records as you intend to process, any
filtering you do afterwards — by indicator type, by age, by status — can consume
the entire page before finding a single usable record. The playbook then reports
"0 indicators" on a module with thousands.

This was observed live: a 10-record fetch sorted oldest-first returned 10 IPs,
so a run configured for domains found nothing, even though domains existed a few
records later.

Fetch a wide window (30 is the hard ceiling the query API applies to this step
regardless of what you ask for), then filter and cap in the code snippet.

**Check:** if the playbook filters after fetching, the fetch limit and the batch
cap must be two different numbers.

---

## 19. Creating a playbook by POSTing a collection leaves the trigger dead

`POST /api/3/workflow_collections` with workflows nested inside creates the
records but does not register the trigger route. The playbook then looks correct
in the UI, reports `isActive: true`, and every attempt to fire it returns
*"No active workflow matching the given route."* Toggling `isActive` does not
fix it.

POST the workflow to `/api/3/workflows` instead, with `collection` pointing at
an already-created collection.

Related, when re-importing after a delete: soft-deleted playbooks keep both
their `uuid` and their `(name, collection)` pair reserved in the recycle bin, so
a re-import 409s with *"a record already exists"* about a playbook you cannot
see. Regenerate every uuid on import, and expect to need a fresh collection name
too.

---

## 20. A manual input cannot be resolved over the API

`cybersponse.action` has no HTTP route (see `triggers.md`), and neither does the
manual input that pauses mid-playbook. The `/api/wf/api/manual-wf-input/{id}/`
endpoint accepts a PUT and returns 200, but the run stays `awaiting` — the
update lands on the record without advancing the workflow.

So even with full appliance access, an API-driven test **stops at the first
manual input**. Everything downstream of it — the decision branches and any
converging result step — stays unexecuted.

**Check:** when a playbook contains a manual input, say plainly which steps were
never reached, and ask the user to click the button once in the GUI. Do not
report the playbook as end-to-end tested.


---

## 21. A Configuration step nothing reads is worse than none

The user asks for a tunable threshold. You add a Set Variable step holding
`malicious_threshold = 10`. Then the scoring snippet opens with:

```python
threshold = 10
```

Everything looks right. The step is there, the value is there, the flow diagram
shows it. But the number the playbook actually uses is the one in the Python,
and editing the Configuration step changes nothing. The user only finds out when
they raise the threshold, re-run, and get identical results.

This is not hypothetical — a generated playbook was measured with **all three**
of its configuration variables dead (`Malicious_Score_Threshold`, `Batch_Limit`,
`Enabled_Indicator_Types`), each one shadowed by a literal in the code.

Every configuration value must be *read* where it is used:

```python
threshold = int("{{ vars.malicious_threshold }}")
max_n     = int("{{ vars.batch_limit }}")
enabled   = "{{ vars.enabled_types | default('ip') }}".lower()
```

Note the quoting: a scalar goes in quoted and cast, an object goes in bare.

The same applies to a Find Records `limit` — if the batch cap lives in
Configuration, the query cannot hardcode a different number, or the two disagree
and the config one is a lie.

**Check:** for every key in every Set Variable step, grep the playbook for
`vars.<key>`. No hit means it is dead. The validator warns on this, but only
looks for the reference — it cannot tell you the code hardcoded the same value
somewhere else, so read the snippet too.


---

## 22. An empty `for_each` block kills the step

A step that does not loop must have **no** `for_each` key. Leaving an empty stub:

```json
"for_each": {"item": "", "parallel": false, "condition": ""}
```

fails the moment the step runs:

```
CS-WF-3: Invalid format of value for for_each loop ''.
The error is 'Expecting value: line 1 column 1 (char 0)'.
```

It does not degrade to "loop over nothing" and it does not skip. The step fails,
and everything downstream stays `incipient`.

This is worth singling out because nothing about it looks wrong. The block is
syntactically valid, it sits alongside legitimate `for_each` blocks on the
enrichment steps, and it survives structural validation. Three independently
generated playbooks all carried it on their Find Records step — a step that
never needed a loop — and all three died there, on the third step, having
enriched nothing.

**Check:** every `for_each` in the file must have a non-empty `item`. If a step
does not loop, delete the key rather than emptying it.


---

## 23. Parallel `for_each` results are not in input order

This is the most dangerous bug in this file, because it produces a **plausible
report with the wrong answers** and nothing anywhere looks broken.

A `for_each` with `"parallel": true` returns its results in **completion order**,
not input order. Aligning them back to the input list by index therefore
attaches each enrichment to the wrong item:

```python
# WRONG whenever parallel is true
ae = abuse[i] if i < len(abuse) else {}
```

Measured on a live appliance, 10 IPs, one parallel AbuseIPDB fan-out:

| Indicator | Score it was given | True score | Result |
|---|---|---|---|
| `8.8.8.8` | 100 | 0 | kept blocked — a public DNS resolver |
| `80.94.95.226` | 0 | 100 | recommended for **unblocking** — 984 abuse reports |
| `141.98.11.62` | 0 | 76 | recommended for **unblocking** |

**6 of 10 were wrong.** The counts still came out as 3 keep / 7 remove — exactly
the right shape, entirely the wrong contents. No error, no warning, nothing in
the JSON to notice.

Two ways to be safe, in order of preference:

1. **Join on a value the response echoes back.** AbuseIPDB returns `ipAddress`;
   build a dict and look each indicator up by it:

   ```python
   ab_by_ip = {}
   for a in ab:
       if a.get("ip"):
           ab_by_ip[str(a["ip"])] = a
   ```

   This is correct whether or not the loop ran in parallel.

2. **Set `"parallel": false`.** Order is then preserved and index alignment
   holds. Slower, but the sequencing is the point.

Never rely on order from a parallel loop. If the response echoes nothing you can
join on, the loop must not be parallel.

**Check:** for every `for_each` with `parallel: true`, find the code that
consumes it. If it indexes by position, it is wrong.


---

## 24. Find Records has no `.data`, and `default([])` hides it

A Find Records step returns its list **directly** at `vars.steps.<Name>`.
Writing `.data` gets you nothing:

```python
records = {{ vars.steps.Get_Oldest_Blocked_IPs.data | default([]) }}   # WRONG
records = {{ vars.steps.Get_Oldest_Blocked_IPs | default([]) }}        # right
```

The `| default([])` is what makes this dangerous. Without it you might notice a
rendering error; with it, the undefined reference becomes a clean empty list.
Observed live: a playbook fetched 30 records, extracted zero, correctly
concluded the batch was empty, took its own empty-batch branch, and finished
**green**. Every step reported success. The only symptom was a review with
nothing in it.

Connector steps are the opposite — they *do* carry `.data`. It is only
Find Records (and `for_each` results, which are lists of envelopes) that do not.

**Check:** grep for `vars.steps.<FindStepName>.data`. There should be no hits.

The execution log on some instances *displays* a Find Records result as
`{"result": [...], "status": ...}`. If you are unsure which shape a jinja
reference will see, this read works for both and costs nothing:

```
(vars.steps.Find.result if vars.steps.Find is mapping else vars.steps.Find) | default([], true)
```

---

## 25. A jinja string in `query.limit` is silently ignored

`"limit": "{{vars.batch_limit}}"` renders to `"10"` — a string. The query API
accepts it and ignores it, returning the 30-record ceiling instead of 10.

Measured directly: integer `10` returned 10 rows; string `"10"` returned 30.
The batch cap the user asked for simply does not apply, and nothing reports an
error.

The same holds for the `?$limit=N` suffix on `module` — omit it and the body
`limit` is ignored too. Both need to be real numbers, set together.

If the cap must be configurable, enforce it in the code snippet after the fetch
(slice the list), not in the query.


---

## 26. A nested object field renders as the string `Array`

If a record field holds a **nested object or list**, every jinja reference to it
renders as the literal five-character string `Array` — not the data. Measured on
a live appliance against an alert whose `sourcedata` was written as an object:

```
{{ vars.input.records[0] }}            -> record.get('sourcedata') == "Array"
{{ vars.input.records[0].sourcedata }} -> the bare token  Array   (a NameError)
{{ vars.sd }}  via a Set Variable      -> "Array"
{{ vars.sd | safe }}                   -> "Array"
a Find Records re-fetch                -> "Array"
```

None of the usual workarounds help. `| safe` does not help. Re-fetching does not
help.

The same alert with `sourcedata` written as a **JSON string** renders correctly
as a dict, with `headers`, `body` and the rest intact. That is how real
integrations store it, so this usually only bites in testing — but when it bites
it is silent. The extraction step parses nothing, every score is zero, and a
phishing playbook returns a confident "not phishing".

**Check:** if extraction returns zero indicators from a message you know is
loaded, print what the injected value actually is before assuming the parsing
logic is wrong. And when seeding test alerts, write `sourcedata` with
`json.dumps(...)`, never as a nested object.

---

## 27. Enriching your own infrastructure manufactures false positives

An email's headers are full of the *recipient's* own infrastructure. Extract
indiscriminately and you will send those to threat intel and score yourself.

Measured on one reported phishing email: 59 indicators were extracted, including
`127.0.0.1`, `10.20.30.40`, and — because the mail transited Office 365 —
`microsoft.com`, `mx.microsoft.com` and `security.microsoft.com`. FortiGuard
returned **`Decoy, ACRStealer C2, ACRStealer`** for all three Microsoft domains,
which then appeared in the verdict as supporting evidence for the message being
phishing.

The verdict happened to be right, on header grounds alone. The reasoning shown
to the analyst was not.

Before enriching, drop:

- private and reserved ranges - `10/8`, `172.16/12`, `192.168/16`, `127/8`,
  `169.254/16`, and the documentation ranges
- your own domain and its mail infrastructure
- the mail platform's own domains - `microsoft.com`, `outlook.com`,
  `protection.outlook.com`, `google.com`, and similar
- standards boilerplate - `w3.org`, `schema.org`

**Check:** count the indicators extracted from one message. If a single email
yields dozens, most of them are infrastructure, and the lookups spent on them
are both wasted and actively misleading.

---

## 28. Strip control characters when extracting from a body

URL and domain extraction over raw text will happily swallow whatever follows,
including line breaks. Observed from a live run - a single "indicator":

```
https://security.microsoft.com/userSubmissionsReportMessage\r\nDISCLAIMER:
```

That is one regex match spanning a URL, a CRLF and the beginning of the next
paragraph. It was then sent to threat intel as a domain.

Normalise before matching: replace `\r` and `\n` with spaces, then split. After
extracting, reject any candidate containing whitespace, a backslash, or a
control character.

**Check:** look at the extracted indicator list itself, not just its length. One
malformed entry means the regex is unanchored.


---

## 29. Date filters take ISO strings, not epochs — and a bare date means midnight

`createDate` and `modifyDate` hold **epoch floats**. So filtering them with an
epoch is the obvious move, and it fails:

```json
{"field": "createDate", "operator": "gte", "value": 1788331664.5}
```

returns HTTP 400 `DriverException`, whose entire message is *"Internal Server
Error. Check log 'prod.log'"*. Nothing tells you the value was the problem.
Measured: epoch float, epoch int, epoch as a string and epoch in milliseconds
all fail. Only ISO strings work:

```json
{"field": "createDate", "operator": "gte", "value": "2026-08-01"}
{"field": "createDate", "operator": "lt",  "value": "2026-09-01"}
```

Both `"2026-08-01"` and `"2026-08-01T00:00:00"` are accepted.

**A bare date is read as midnight**, which makes an inclusive end bound wrong in
a way that quietly drops a day. Measured on a module holding a record created
2026-09-01 at 07:12:

| filter | rows |
|---|---|
| `lte "2026-09-01"` | **0** — the record is after midnight |
| `lt "2026-09-02"` | 1 |
| `lte "2026-09-01T23:59:59"` | 1 |

So express "everything up to and including the 31st" as `lt` the **1st of the
next month**, not `lte` the 31st.

A relative window - "the last 7 days" - therefore has to be computed as a date
before it goes into the filter, not left as arithmetic on a timestamp. A
scheduled playbook was generated with
`"value": "{{ arrow.utcnow().timestamp() - 604800 }}"`, which renders a number
and 400s on every run.

**Check:** no filter on a date field may carry a number, a numeric string, or a
jinja expression built from `timestamp()`.


---

## 30. The jinja loop and the code reading it drift apart

A code snippet usually starts by building its input with a jinja loop:

```python
records = [{% for r in vars.steps.Find_Blocked_Records %}{"value": "{{ r.idicator }}", "ticket_missing": ...}{% endfor %}]
```

and then reads it further down:

```python
ticket = record['ticket']          # never built - KeyError, step dies
```

Nothing about this looks wrong. The loop is valid, the python is valid, and the
two are written far enough apart that the mismatch is easy to miss. Observed in
a generated playbook: the loop built `value`, `ticket_missing` and
`firewall_missing`; the code read `record['ticket']`, `record['firewall']` and
`record['id']`. The step failed with `KeyError: 'ticket'` and the run stopped.

Two habits prevent it:

- **Build and read the same names.** After writing the loop, list its keys, then
  check every access against that list.
- **Use `.get(key, default)`, never `[key]`,** on anything derived from record
  data. A record with a null field, a differently-shaped response, or a renamed
  key then degrades instead of killing the run.

**Check:** grep the snippet for `['` and confirm every bracketed key appears in
the jinja loop that built the structure.


---

## 31. `query.limit` on a Find Records step does nothing

This is the one that quietly decides how much of a module a playbook ever sees.

A Find Records step carries both a `module` string and a `query` object, and the
obvious place to set the page size is `query.limit`. **It is ignored.** Measured
on a live appliance against a module holding 550 records:

| `module` | `query.limit` | rows returned |
|---|---|---|
| `alerts` | 5 | **30** |
| `alerts` | 30 | **30** |
| `alerts` | 1000 | **30** |
| `alerts?$limit=200` | 200 | **200** |
| `alerts?$limit=1000` | 1000 | **550** (all of them) |

The page size lives in the **`module` string**, as a `$limit` query parameter.
`query.limit` is decoration. Thirty is simply the platform default, which is why
a step that never sets `$limit` looks like it has a hard 30-record ceiling — one
generated playbook described exactly that as "the documented 30-record Find
Records page ceiling" and built its whole design around it, sweeping 30 of 550
alerts.

`$page` works there too, so `alerts?$limit=200&$page=2` is the second page.

**So:**

- Put the size where it is read: `"module": "alerts?$limit=500"`.
- Set `query.limit` to the same number anyway — harmless, and it stops the next
  reader assuming the step is capped.
- If the module can outgrow one page, page explicitly rather than hoping.

## 32. "Examined 30 of 30" when there are 550

A Find Records step returns a **bare list of rows**. No `@totalCount`, no
`hydra:totalItems`, nothing describing the population it was drawn from. So this
looks careful and is not:

```python
total_available = len(records)
if isinstance(sweep_result, dict):
    total_available = sweep_result.get("@totalCount", total_available)
```

The dict branch never fires, `total_available` collapses to `len(records)`, and
the report says **"Alerts examined: 30 of 30 available — the full records
returned by the alerts query were analyzed."** That is worse than saying nothing:
it converts *I don't know how much I missed* into a confident claim of full
coverage. Observed in a playbook whose brief specifically asked it to be honest
about limits — it built the honesty machinery and then fed it a number it had
made up.

A count of what you fetched is not a count of what exists.

**So:**

- To state coverage, fetch the total separately — a second Find Records step
  with `$limit=1` on the same filters and read the module count, or just raise
  `$limit` until you have the whole population (pitfall 31).
- If you genuinely cannot get a denominator, say **"examined 30 records
  (population unknown)"**. Never `N of N` derived from one list.
- Only claim "full sweep" when the row count came back **below** the `$limit`
  you asked for — that is the one case where a short page proves you reached
  the end.


---

## 33. A code snippet that renders the whole record fails with a bare 500

Rendering an entire alert into the code — `raw = {{ vars.input.records[0].sourcedata | tojson }}`
— puts every byte of it into the code-snippet request. Measured on a production
instance: a reported-phishing alert whose `sourcedata` carried the reporter's
original message with inline base64 images was **2.3 MB**, and the step failed
with only this:

```
500 Server Error: Internal Server Error for url: https://localhost:9595/integration/execute/?format=json
<h1>Server Error (500)</h1>
```

No traceback, no field name, nothing pointing at size. The same playbook ran
cleanly once the jinja built a trimmed dict first — about **60 KB**, and a
deliberately worse 250 KB case also passed.

Build the input in jinja and pass only what the code reads, capping large text:

```
{{ {'headers': sd.headers, 'body': {'text': (sd.body.text | default('', true) | string)[:50000],
    'html': (sd.body.html | default('', true) | string)[:200000]}} | tojson }}
```

Links and indicators live in the markup, not in the base64 image data that makes
these emails huge, so the cap costs nothing in practice. The validator warns
when a snippet renders a whole record.

Two more sources of bulk, both measured on a production phishing build:

- **Inline images inside the HTML body.** A capped `html[:200000]` can still be
  mostly base64. Cut the `data:...;base64,` payloads out in jinja before capping:

  ```
  {% set h = (b.html | default('', true) | string) %}
  {% if ';base64,' in h %}{% set ps = h.split(';base64,') %}{% set ns = namespace(o=ps[0]) %}
  {% for p in ps[1:] %}{% set q = p.find('"') %}{% set ns.o = ns.o + ';base64,' + (p[q:] if q >= 0 else '') %}{% endfor %}
  {% set h = ns.o %}{% endif %}
  ```

- **Threat-intel loop results.** Each VirusTotal envelope carries
  `last_analysis_results` — one entry per engine, ~90 of them — plus whois text.
  Five lookups rendered whole add hundreds of KB. Build a trimmed list in jinja
  with only what the code reads (`id`, `last_analysis_stats`, and the few
  attributes used), and collect detection names in the loop instead of passing
  the whole results map. See `connector-responses.md`.

Keep the **rendered** snippet under roughly 150 KB; measure it in a test render
(code plus injected data), not only the template.

---

## 34. `sourcedata` is often a string, and a string has no fields

Ingestion playbooks commonly write `sourcedata` with `| toJSON`, so the field
holds a **JSON string**. Then `sd.body`, `sd.headers` and `sd is mapping` all
quietly yield nothing — no error, just an empty extraction. (Pitfall 26 is the
mirror image: a nested object that renders as `Array`.)

Handle both shapes explicitly:

```
{% set sd = vars.input.records[0].sourcedata %}
{% set sd = sd if sd is mapping else (sd | default('{}', true)) | toDict %}
```

`toDict` is a FortiSOAR filter, production-verified. A Set Variable step that
assigns `{{ vars.input.records[0].sourcedata }}` also converts a JSON string
into an object — but then the full payload is stored in that step's output on
every run, which bloats the execution history.

Also expect the shape to **change after creation**. Observed on real
FortiSIEM-ingested alerts: the ingestion first stores `incident_data` alone and
later adds the events, giving
`{"incident_data": {...}, "associated_events": [ {...}, ... ]}` — the key is
**`associated_events`**, not `events`. A playbook triggered on create can see
either shape, so read both, and guard the event list with `is defined` first
(pitfall 39). The full field-by-field shape — display-name attribute keys with
spaces, `incidentDetail` as a JSON string, epoch-millisecond times — is in
`fortisiem-queries.md`, "FortiSIEM-ingested alert sourcedata".

---

## 35. A skipped step makes its own reference an error

With `when` false, or a lookup switched off, the step never runs and
`vars.steps.<Name>` is undefined. `vars.steps.<Name>.data` then fails to render
instead of producing an empty value. This bites precisely the playbooks that
were built well — the ones with optional enrichment that can be switched off or
deleted.

```
(vars.steps.AbuseIPDB_Lookup | default({}, true)).data | default({}, true)
```

Guard every reference to a step that is conditional, switchable, or that a user
might delete. For a code snippet input, `{{ vars.steps.X | default([]) | tojson }}`.

---

## 36. Copying a playbook: change only its OWN ids

Adapting a playbook for another client usually means copying it and giving the
copy fresh uuids, so importing it cannot overwrite the original. Regenerating
**every** uuid in the file is the obvious way to do that, and it is wrong:
the file also contains ids that point **outside** the playbook, and changing
them breaks it. Measured: a blanket remap rewrote the
`stepType` of every step — Start, Manual Input, Decision, Set Variable — to ids
that exist on no FortiSOAR, and the file would not have imported.

Replace only: the collection uuid, the workflow uuid, every step uuid, every
route uuid (and the references to those — `triggerStep`, `sourceStep`,
`targetStep`, decision `step_iri`, manual-input option `step_iri`, timeout
`step_iri`). Leave alone: `stepType`, `workflowReference`, connector `config`,
picklist and tag IRIs, `priority`, `playbookOrigin`.

Two more traps when copying:

- **Importing the original export a second time overwrites the original.** The
  file carries its playbook's uuid. Use Clone in the UI, or remap as above.
- **A copied Manual Input keeps `message.parentstepid`**, which FortiSOAR
  rewrites on import and which now points into the old playbook. Delete the key;
  FortiSOAR sets it again.

The validator errors on any `stepType` outside the documented set, and warns on
a foreign `parentstepid`.

---

## 37. Sub-playbook argument names differ between clients

Two clients' "Domain Block" sub-playbooks, built separately, take the same
information under different names — `DomianList` + `Ticket` in one,
`Domain_List` + `Ticket_id` in the other. FortiSOAR does not reject an argument
the child never declared: the child receives nothing for it, often finds an
empty list, and **succeeds** having blocked nothing.

Read the child's `parameters` (or its Start step inputs) from an export before
wiring a Reference step, and re-check them every time a playbook is adapted for
another client. The validator checks argument names whenever the child is in
the same file.

---

## 38. Uploading a file is not attaching it to the record

`upload_file_to_cyops(..., create_attachment=True)` creates a standalone
Attachment record. It does **not** appear on the alert: the report exists, and
nobody reading the alert can find it. Link it with an Update Record step
(production-verified):

```json
"resource": {"attachments": "{{ vars.steps.Build_Report.data['code_output']['attachment_iris'] }}"},
"operation": "Append",
"collection": "{{ vars.input.records[0]['@id'] }}",
"collectionType": "/api/3/alerts",
"fieldOperation": {"attachments": "Append"}
```

Guard it with `when` on the attachment iri being non-empty, so a failed build
does not attach an empty link. See `reports.md`.

---

## 39. An undefined value passes `is sequence` and `is iterable`

A guard that looks safe lets a missing field straight through:

```
{% set evs = sd.associated_events if sd.associated_events is sequence else [] %}{{ evs[:50] }}
```

On an alert with no `associated_events`, Jinja's undefined value tests **true**
for both `is sequence` and `is iterable` (measured with jinja2:
`x.missing is sequence → True`, `x.missing is defined → False`). The guard
passes, and `[:50]` then raises `UndefinedError` — the step fails on exactly the
alerts the guard was written for.

Test `is defined` **first**, and exclude strings and mappings, which are also
iterable:

```
{% set v = sd.associated_events %}
{% set evs = v if (v is defined and v is iterable and v is not string and v is not mapping) else [] %}
```

The same applies to any optional list: event lists, attachments, loop outputs.

---

## 40. `sorted()` on tuples crashes when two first values are equal

`sorted([(t, {...}), (t, {...})])` compares the second elements when the first
are equal, and two dicts cannot be compared:
`TypeError: '<' not supported between instances of 'dict' and 'dict'`.
FortiSIEM events routinely share a timestamp, so this fails on real data and
passes on a hand-made sample.

Add a unique tie-breaker and read the row from the last position:

```python
pairs = []
i = 0
for ev in events:
    pairs.append((ev_time(ev), i, ev))
    i = i + 1
ordered = [p[2] for p in sorted(pairs)]
```

Or sort a list of scalars (times, names) and look the rows up afterwards.

---

## 41. Two playbooks writing back the same alert or SIEM incident overwrite each other

Closing an alert, or clearing its FortiSIEM incident, is rarely the only thing
that reacts to a status change. Observed on a client instance: an existing
on-update playbook cleared the FortiSIEM incident as **False Positive** whenever
an alert's status became *Closed*. A new playbook closed alerts and cleared the
incident as **True Positive** — and the existing playbook then fired on the same
status change and overwrote the resolution.

Before adding any close-alert or SIEM write-back step:

- **Ask** whether other playbooks trigger on alert updates (status, severity,
  tags) and what they write back. You cannot see this from the export you were
  given.
- Let **one** playbook own the write-back. If both must stay, tag alerts the new
  playbook has already synced (e.g. `fsm-cleared`) and add *"Tags does not
  contain fsm-cleared"* to the other playbook's trigger.
- Say on delivery which existing playbook is affected and what the user must
  change in it.

---

## 42. A placeholder response step must not record an outcome

When the client's block method is not decided yet, the block step is delivered
as a placeholder (a Set Variable or no-op). Every step **after** it on that
branch still runs. If those steps tag the alert `blocked`, close it as resolved,
or clear the SIEM incident as *True Positive – blocked*, the record now says
something was blocked that never was — the most dangerous kind of wrong record,
because nobody re-checks a closed alert.

While a response step is a placeholder:

- branches after it write **no** "blocked / contained / resolved" outcome to the
  alert or the SIEM;
- the result carries an explicit `PENDING_BLOCK_ACTION` (or similar) status and
  the alert stays open;
- the delivery message lists the placeholder and the write-back to add when the
  real action replaces it.

---

## 43. `urlencode` turns spaces into `+` — decode with `unquote_plus`

Rendering free text (email bodies, subjects, command lines) straight into a code
snippet as `X = {{ v | tojson }}` works until the text contains something the
template or the request does not survive. The robust form is to URL-encode the
JSON and decode it in Python:

```python
from urllib.parse import unquote_plus
X = json.loads(unquote_plus("{{ v | tojson | urlencode }}"))
```

**Use `unquote_plus`, not `unquote`.** FortiSOAR's `urlencode` encodes a space as
`+`. Measured on a production instance: with `unquote` the JSON came back as
`{"body":+{"text":+...` and the step failed with
`400 ... JSONDecodeError: Expecting value: line 1 column 20`. `unquote_plus`
turns the `+` back into spaces; a literal `+` in the text arrives as `%2B` and is
decoded correctly. The validator warns on `urlencode` with `unquote(`.

The encoded text stays pure ASCII, so the rendered snippet has no quoting,
escaping or encoding surprises whatever the email contains.

---

## 44. Emoji in a code snippet's data make the step fail with a bare 500

Measured on a production instance: a phishing alert whose body contained emoji
(`🔐 💰 ✅`) failed its code snippet with only
`500 Server Error ... /integration/execute/`, after about a second. Every other
alert passed. `tojson` escapes non-ASCII as `\uXXXX`, and characters above U+FFFF
— most emoji — travel as **surrogate pairs** (`🔐`). After the round
trip through the snippet, a lone or re-encoded surrogate in the step's input or
output cannot be stored, and the platform reports nothing more specific.

Strip them as soon as the data is decoded, and before anything is printed:

```python
def scrub(o):
    if isinstance(o, builtins.dict):
        out_ = {}
        for k_ in o:
            out_[scrub(k_)] = scrub(o[k_])
        return out_
    if isinstance(o, builtins.list):
        return [scrub(x_) for x_ in o]
    if isinstance(o, builtins.str):
        return "".join([ch for ch in o if not (0xD800 <= ord(ch) <= 0xDFFF or ord(ch) > 0xFFFF or ord(ch) == 0)])
    return o

RAW = scrub(RAW)
```

This keeps ₹, accented letters, Arabic and other BMP text; only emoji, stray
surrogates and NUL go. Emoji carry nothing an analysis needs. `reports.md`
covers the separate case of emoji inside a generated PDF.

---

## Pre-delivery checklist

Structural:
- [ ] every step's uuid appears as a route `sourceStep` unless genuinely terminal
- [ ] every Decision `conditions[].step_iri` has a matching route
- [ ] `triggerStep` points at the Start step; `collection` matches the parent uuid
- [ ] step and variable names are underscore/space only

Wiring:
- [ ] every connector step has a real `config` and `version`, or an explicitly flagged placeholder
- [ ] every step whose output is consumed declares it in `step_variables` with the full `vars.steps.<Name>...` path
- [ ] `vars.result` only inside a connector step's own `step_variables`
- [ ] no code snippet renders a whole record or `sourcedata` — trimmed dict only (pitfall 33)
- [ ] `sourcedata` read through `is mapping` / `toDict`, not assumed to be a dict (pitfall 34)
- [ ] every optional list guarded with `is defined` first, not only `is sequence` / `is iterable` (pitfall 39)
- [ ] every `vars.steps.X` that can be skipped is guarded (pitfall 35)
- [ ] a copied or cloned playbook changed only its OWN ids (pitfall 36)
- [ ] every sub-playbook argument name matches the child's `parameters` (pitfall 37)
- [ ] a generated file is linked to the record, not only uploaded (pitfall 38)
- [ ] cloned steps reference themselves, not their source

Code snippets:
- [ ] no banned builtin, in code **or comments** — grep for each word in the banned list
- [ ] `true, false, null` aliased at the top
- [ ] exactly one `print(json.dumps(...))`
- [ ] free text injected as `json.loads(unquote_plus("{{ x | tojson | urlencode }}"))`, never decoded with `unquote` (pitfall 43)
- [ ] decoded data scrubbed of emoji, surrogates and NUL before use and before printing (pitfall 44)
- [ ] any `sorted()` over tuples carries a unique tie-breaker (pitfall 40)
- [ ] result parsing unwraps `result` → `data.events[].attributes`, drops `attribute`, uses `@totalCount`

Queries:
- [ ] every generated `cond` has balanced parens, even quote count, no backslash before a closing quote, no doubled backslashes
- [ ] every attribute confirmed populated for its event type, or flagged for the user to verify
- [ ] tenant scope present
- [ ] window capped on any query over a high-volume table
- [ ] identical queries deduplicated

Honesty:
- [ ] a failed or missing query is reported as not-run, never as clean
- [ ] no step after a placeholder response action records "blocked", "contained" or "resolved" (pitfall 42)
- [ ] other playbooks that react to alert updates were asked about before adding close-alert or SIEM write-back steps (pitfall 41)
- [ ] coverage gaps stated in the output
- [ ] thresholds carry a note recording the measurement behind them
