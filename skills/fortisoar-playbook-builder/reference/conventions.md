# Conventions & Safety Rules

## Naming — strict rule

**Step names, variable names, and playbook names: underscores and spaces only. No other special characters** (no `/`, `-`, `.`, `#`, `:`, `(`, `)` inside a name).

Exception: the playbook's own top-level `name` may include brackets for human labelling, e.g. `TTP Sweep - Ransomware Kill Chain [FortiSIEM][Scheduled]`. **Step names and variable names must stay strictly underscore/space only** — they are referenced in jinja as `vars.steps.<Step_Name>` and a stray character breaks the reference.

### A space in the step NAME becomes an underscore in the REFERENCE

This is the single most common way a generated playbook runs green and does
nothing. The name and the reference are not the same string:

| Step name (in `"name"`) | Jinja reference |
|---|---|
| `Get Oldest Blocked IPs` | `{{ vars.steps.Get_Oldest_Blocked_IPs }}` |
| `Enrich AbuseIPDB` | `{{ vars.steps.Enrich_AbuseIPDB }}` |
| `Analyse Email` | `{{ vars.steps.Analyse_Email.data['code_output'] }}` |

Writing `{{ vars.steps.Get Oldest Blocked IPs }}` does not resolve. Jinja reads
`vars.steps.Get` and then hits a bare word. **It does not raise** — the
expression yields nothing, the `for_each` iterates an empty list, the code
snippet gets an empty payload, and the playbook finishes successfully having
enriched nothing.

Every place this matters: `for_each.item`, code-snippet injections, decision
conditions, manual-input bodies, and Set Variable values.

**Check before delivering:** every `vars.steps.` reference in the whole file must
match a real step name with spaces replaced by underscores. This was observed in
a real generated playbook — all seven references carried spaces, and the
structural validator passed it with zero errors.

Good step names: `Run_TTP_Query`, `Build_Query_Plan`, `Check Attachments`, `SetResult_Not Found`.

## UUIDs

Generate a fresh uuid4 for every object (`WorkflowCollection.uuid`, `Workflow.uuid`, every `WorkflowStep.uuid`, every `WorkflowRoute.uuid`). Generate them programmatically with code execution — a malformed or duplicate uuid breaks the import.

---

# Connector configuration — harvest it, never hardcode it

This is the most common complaint about generated playbooks: the connector step has no usable `config`, so the playbook imports but cannot run.

Config uuids, connector versions and picklist uuids belong to **one FortiSOAR instance**. They cannot be guessed, they differ per tenant, and they change. Baking a set into this skill would produce playbooks that are wrong for everyone except the instance they were copied from.

## The mechanism: a reference playbook

Ask the user, once, for **one playbook export from their instance that contains the connector steps they use** — ideally a single playbook touching FortiSIEM, the code snippet, threat intel, and anything else in regular use. Then harvest from it:

```
python3 scripts/extract_connector_configs.py <reference.json> [more.json ...]
```

It prints every connector with its `config`, `version` and the operations seen, plus a JSON reuse block, plus any picklist uuids and sub-playbook references. Use those values directly in the generated playbook.

**How to ask, if no reference has been provided yet:**

> "Send me any one playbook export from your FortiSOAR that uses the connectors you want — FortiSIEM, code snippet, threat intel, whatever's in play. I'll pull the connector config UUIDs and versions from it so the playbook I generate imports ready to run instead of needing manual wiring."

Ask before generating, not after. A playbook delivered with placeholder configs has to be hand-edited on every step, which is exactly the complaint this avoids.

## Order of preference

1. **A reference playbook has been provided** (this conversation or earlier) → harvest with the script.
2. **The user already uploaded a playbook for another reason** → harvest from that; do it without being asked.
3. **Neither, and the user is unreachable** → use a clearly-marked placeholder and say so prominently in the delivery message, not buried:

```json
"config": "<SET_FORTISIEM_CONFIG_UUID>"
```

## If the new playbook needs a connector the reference did not contain

Do not guess and do not reuse a different connector's uuid. Ask for that one specifically:

> "The reference didn't include eScan EDR — can you send a playbook that uses it, or paste its config UUID from the connector's Configurations tab?"

## The same rule covers

- **`version`** on a connector step — a wrong value is rejected at execution
- **picklist uuids** (severity, status, state, type)
- **`workflowReference`** on a sub-playbook step

All three are instance-specific and all three come from the reference playbook.

---

# Step variables — the mechanism that makes data flow

A step's output is **not** automatically available downstream. Declare it in that step's `step_variables`, using the fully-qualified path.

```json
"step_variables": {
  "plan_meta":  "{{ vars.steps.Build_Query_Plan.data['code_output'] }}",
  "query_plan": "{{ vars.steps.Build_Query_Plan.data['code_output']['plan'] }}"
}
```

Downstream steps then read `{{vars.plan_meta}}`.

**`vars.result` means one thing only: the current step's own output, inside that step's `step_variables`.** Production-verified on a connector step:

```json
"step_variables": {
  "total_incidents": "{{ ((vars.result.data or {}).result or {}).total or 0 }}"
}
```

Anywhere else it does not exist — in a later step it renders empty, a decision reading it takes the false branch, and the playbook "succeeds" having done nothing. (It resolves elsewhere only if some Set Variable happens to define a key called `result`, which is a coincidence, not a reference.) For a Code Snippet's own output use the table below.

| Step type | Declare in `step_variables` as |
|---|---|
| Code Snippet | `{{ vars.steps.<Name>.data['code_output'] }}` |
| Connector Operation | `{{ vars.steps.<Name> }}` |
| Connector Operation with `for_each` | `{{ vars.steps.<Name> }}` — result is a **list**, one entry per iteration |

Renaming a step means updating every `step_variables` entry referencing it, **including its own**. Cloning a step is the classic way to get this wrong: the clone keeps the original's name inside its own expression and reads the wrong step's output.

---

# Native step or Code Snippet?

The sandbox is the least stable part of FortiSOAR: upgrades have withdrawn
builtins, turned `list` into a shim, and changed what a snippet may import. A
snippet that fails takes its whole step down with a bare 400 or 500 and no
traceback. Native steps and Jinja do not change under you, and an analyst can
maintain them in the designer. Reach for a Code Snippet last.

| Job | Use | Not |
|---|---|---|
| Pull fields out of the alert / sourcedata | Set Variable with Jinja (`toDict` for string sourcedata) | a snippet that only copies fields |
| Branch on a value | Decision | a snippet returning a flag |
| Switch a lookup on/off | `when` on that step + a Configuration variable | `if` inside a snippet |
| Loop a lookup over indicators | connector `for_each` (`parallel: false` when you join by order) | a snippet calling APIs |
| Build a short list or filter one | Set Variable with a `namespace` loop | a snippet |
| Resolve a picklist | `'AlertStatus' \| picklist('Closed', '@id')` | a hard-coded IRI |
| Find / create / update / link records, add a comment | Find / Create / Update Record steps | `make_request` in a snippet |
| Parse raw logs or free text, regex | **Code Snippet** | |
| Score several sources and explain the verdict | **Code Snippet** | |
| Join fan-out results, time arithmetic across sources | **Code Snippet** | |
| HTML/PDF report, file upload | **Code Snippet** (`reports.md`) | |

When you do write one:

- one snippet per job — not one per field, not one for the whole playbook;
- the portable subset below, nothing clever (no classes, no `lambda`, no
  generators that hide a banned builtin);
- wrap the risky part in `try` and return an error field, so the step reports
  rather than dies; give a non-critical snippet `ignore_errors: true`;
- inject only the fields it reads (pitfall 33).

---

# Python Code Snippet — the sandbox is restrictive

## Injecting upstream data

```python
import json
true, false, null = True, False, None      # jinja may render JSON literals

plan_meta = {{vars.plan_meta}}
raw       = {{vars.sweep_results | default([])}}
threshold = int("{{vars.min_score_to_alert}}")
```

FortiSOAR renders the jinja first, so the result must be valid Python. Alias `true/false/null` at the top of every snippet.

Note the quoting difference: an injected **object** goes in bare (`{{vars.plan_meta}}`); an injected **scalar** goes in quoted and cast (`int("{{vars.hours}}")`).

## Find Records page size

`query.limit` is ignored. The page size is the `$limit` in the **module string**:

```json
"module": "alerts?$limit=500",
"query": {"limit": 500, "logic": "AND", "filters": [], "sort": []}
```

Without a `$limit` the step returns the platform default of **30 rows**, whatever
`query.limit` says. Measured; see pitfall 31.

## Restricted built-ins — the definitive list

**Allowed:** `list`, `dict`, `tuple`, `str`, `int`, `float`, `bool`, `len`, `sorted`, `zip`, `abs`, `round`, `isinstance`, `range`, `print`

**`isinstance(x, list)` depends on the instance — write the portable form.**
On the lab appliance `isinstance(x, list)` raises *"isinstance() arg 2 must be a type"*: `list` resolves to a shim, not a real type (`dict`, `tuple`, `str`, `int`, `float` and `bool` all work). On two production instances the same call runs fine — measured on playbooks that returned output. You rarely know which kind of instance a playbook will be imported into, so write the form that works on both:

```python
import builtins
LIST_T = builtins.list          # production-verified alias
DICT_T = builtins.dict

if isinstance(x, DICT_T):
    ...
elif isinstance(x, LIST_T):
    ...
```

or branch on `isinstance(x, dict)` first and iterate inside a `try`. The validator reports a bare `isinstance(x, list)` as a warning.

**The banned list below is from the lab appliance.** Some production snippets on other instances contain `lambda`, `max()` or `enumerate()` — whether those steps actually succeed was not confirmed. Treat the list as the safe portable subset: code that avoids it runs everywhere.

**Banned — measured, not assumed:** `set`, `any`, `all`, `enumerate`, `sum`,
`max`, `min`, `type`, `eval`, `exec`, `map`, `filter`, `open`, `reversed`

**Also allowed, despite looking like the ones above:** `sorted`, `zip`, `abs`,
`round`. These were previously listed here as banned. They are not — each was
executed successfully in the sandbox. Do not hand-roll a sort; `sorted` works.
**But sorting tuples needs a unique tie-breaker:** `sorted([(t, row), ...])`
raises `TypeError` when two `t` values are equal and the rows are dicts. Sort
`(t, index, row)` and read `p[2]` (pitfall 40).

The failure is not graceful: the connector rejects the whole step before
execution with a 400 naming the builtin —
`Invalid code snippet: Uses of ['max'] is restricted in the code snippet`.
One `max()` fails the playbook.

**The check is on the call, not the text.** A banned word inside a comment, a
docstring, a string literal, or an identifier is fine — `usage_type`,
`indicator_type` and `# avoids enumerate` all execute without complaint. Only an
actual call to the builtin is rejected. (An earlier version of this file claimed
the match was textual. It is not; that was measured wrong.)

## FortiSOAR jinja filters and behaviours worth knowing

Production-verified on the instances this skill was built against:

| Filter / behaviour | Use |
|---|---|
| `x \| toDict` | parse a JSON **string** into a dict — `sourcedata` is often stored as a string, and then `sd.field` and `sd is mapping` both fail silently |
| `x \| toJSON` | serialise for storage, e.g. writing `sourcedata` |
| `'Severity' \| picklist('Critical')` | resolve a picklist item by its display value — no instance-specific IRI in the file |
| `'AlertStatus' \| picklist('Closed', '@id')` | the item's IRI, ready for an Update Record field. Verified on a lab appliance for `AlertStatus` → Closed, `Closure Reason` → False Positive / Duplicate and `AlertState` values. The list and item names must exist on the instance — `AlertState` has no "Enriched" value by default, so mark enrichment with a tag instead |
| `x \| tojson` | sorted keys, and every non-ASCII character escaped as `\uXXXX` — emoji become surrogate pairs (pitfall 44) |
| `x \| urlencode` | encodes a **space as `+`** — decode with `unquote_plus`, never `unquote` (pitfall 43) |
| `{% set ns = namespace(o=[]) %}{% for … %}{% set ns.o = ns.o + [x] %}{% endfor %}{{ ns.o }}` | build a list in a Set Variable without a code step; the value arrives downstream as a real list |
| a step with `"when": "{{ … }}"` that renders false | is **skipped**, and the flow continues to its successor |
| several branches converging on one step, some of them skipped | the join still runs once the executed branches finish |

**Guard every reference to a step that can be skipped.** A step whose `when` was false, or that you later delete, leaves `vars.steps.<Name>` undefined, and `vars.steps.<Name>.data` is then an error, not an empty value. Write:

```
(vars.steps.Get_Events | default({}, true)).data
```

(Measured against Jinja2's standard undefined handling; the appliance's handling of this case was not separately confirmed — guarding costs nothing either way.)

**Guard optional lists with `is defined` first.** `x.missing is sequence` and
`x.missing is iterable` are both **true** for an undefined value, so they are
not guards on their own (pitfall 39):

```
{% set v = sd.associated_events %}
{% set evs = v if (v is defined and v is iterable and v is not string and v is not mapping) else [] %}
```

## Jinja `default('')` does not catch a JSON null

`{{ r.ticketId | default('') }}` renders the string **`None`** when the field is
JSON `null`, because the value is defined — it is just null. That `"None"` then
lands in your report and your record IRIs.

Use the second argument, which treats any falsy value as missing:

```
{{ r.ticketId | default('', true) }}
```

Apply it to every optional field you pull out of a record or a connector reply.

## Safe replacements

| Instead of | Write |
|---|---|
| `max(a, b)` | `if b > a: a = b` |
| `max(xs)` | loop with a running `best`, or `sorted(xs)[-1]` — `sorted` is allowed |
| `sum(xs)` | loop with a running `total` |
| `any(cond for x in xs)` | loop setting a `found = True` flag |
| `all(...)` | loop setting `ok = False` on first failure |
| `set(xs)` | a dict as a set: `seen[x] = True`, then `for k in seen` |
| `enumerate(xs)` | manual index: `i = 0` … `i = i + 1` |
| `sorted(xs, key=lambda ...)` | insertion sort with an explicit comparison |
| set intersection `a & b` | loop over one dict testing `if k in other` |
| `type(x) == list` | duck-type it - see the caveat below |

`sorted()` on a plain list of comparable values is allowed. `sorted()` with a `key=` callable is not worth the risk — write the insertion sort.

Comprehensions are fine provided they call no banned builtin.

## Output

End with a single `print(json.dumps({...}))`. That becomes `vars.steps.<Step_Name>.data['code_output']`. Print nothing else — downstream parsing takes the last line.

---

# Jinja and JSON hazards that cause a 400

The connector validates the request body before it reaches FortiSIEM. **A 400 within a few seconds is a validation rejection — a malformed field, not load.** A genuine timeout takes minutes.

**Never end a quoted value with a backslash.**

```
BAD   procName CONTAIN "C:\Users\Temp\"     -- \" reads as an escaped quote; string never closes
GOOD  procName CONTAIN "C:\Users\Temp"
```

**Use single backslashes in query strings.** Doubling them produces a literal `\\` that matches nothing — the query runs, returns zero rows, and looks like a clean environment.

**Keep the payload free of characters that break JSON encoding** — literal newlines, unescaped quotes, `$`. If a value must carry them, base64-encode it and decode on the far side.

**Validate the generated conditions, not the code that generates them.** Run the plan-building snippet and check each produced `cond` for balanced parentheses, an even number of double quotes, no backslash before a closing quote, and no doubled backslashes.

---

# Time helper

`getRelativeDate(years, months, days, hours, minutes, seconds, ["start"|"end"])` — e.g. `{{getRelativeDate(0,0,0,-3,"start","start")}}` for "3 hours ago, start of hour."

Prefer absolute `from`/`to` computed in a Code Snippet for anything the playbook must reason about later.
