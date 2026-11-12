# Validation checklist: check the JSON before delivering it

Read this at step 6 on every build. It is the full list of mechanical checks a
playbook must pass, written so you can run it by reading the generated JSON.
Every item comes from a playbook that imported cleanly and then failed, or ran
green and did nothing.

The same checks exist as a Python program, `validate_playbook.py`, in the
optional tools repository (github.com/git-Jimit/fortisoar-playbook-tools). If
the user has it and you can run code, run it as well. It parses every Jinja
template and does not tire on a 40-step playbook. This checklist is the
reference either way: the program implements it, not the other way round.
Two items, 3.3 and 4.5, need a reader and are not in the program.

## How to use it

- **Severity.** Each check is marked ERROR, WARN or INFO.
  - ERROR: the playbook fails to import, fails at run time, or silently does the wrong thing.
  - WARN: it imports and runs, but will hurt at run time or mislead the analyst.
  - INFO: expected and acceptable. Mention it on delivery.
- **Delivery bar: 0 errors and 0 warnings.** Fix every ERROR and WARN. If you
  knowingly leave a WARN, name it and the reason in the delivery message.
- **Scope.** Run the checks on every workflow in `data[].workflows[]`, not only
  the one you edited. Where a check says *built from scratch*, it applies to
  objects whose `id` and `createDate` are `null`. Uploaded exports have real
  values there and are held to a softer rule.
- **Method.** Work from the file, not from memory of what you meant to write:
  1. List every step as `name`, `uuid`, `stepType` (last path segment), `top`, `left`.
  2. List every route as source name → target name.
  3. Collect every string in `arguments` that contains `{{` or `{%`.
  4. Then go through the sections below in order.

  If you can run code but do not have the tools repository, a throwaway script in
  your scratch area that loads the JSON and prints those three lists makes the
  pass faster and more reliable. Do not ship it.

The fixed step-type uuids used below are listed in `step-types.md`. The ones the
checks refer to:

| Short name | stepType uuid |
|---|---|
| Connector | `0bfed618-0316-11e7-93ae-92361f002671` |
| Code Snippet | `1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8` |
| Set Variable | `04d0cf46-b6a8-42c4-8683-60a7eaa69e8f` |
| Decision | `12254cf5-5db7-4b1a-8cb1-3af081924b28` |
| Manual Input | `fc04082a-d7dc-4299-96fb-6837b1baa0fe` |
| Find Records | `b593663d-7d13-40ce-a3a3-96dece928770` |
| Update Record | `b593663d-7d13-40ce-a3a3-96dece928722` |

---

## 1. File and collection

**1.1 The envelope parses: ERROR.** The file is valid JSON of the form
`{"type": "workflow_collections", "data": [...], "exported_tags": []}`, and
`data` holds at least one collection. A file with no collections is an error.

**1.2 `workflow.collection` points at the parent collection: ERROR when built from scratch, WARN on an export.**
Each workflow's `collection` must be `/api/3/workflow_collections/<uuid>` with
the parent collection's `uuid`. A single-playbook export legitimately points at
its real home collection instead. Leave that alone (`playbook-schema.md`).

**1.3 Playbook `description` is 255 characters or fewer: ERROR.** Count the
characters of every workflow's `description`, including spaces. Longer text
belongs in the delivery message or in the Configuration step, not in the
description.

## 2. Steps and step types

**2.1 Every `stepType` is a known type: ERROR.** The uuid must be one listed in
`step-types.md` or `triggers.md`. Anything else is a typo, or the result of
regenerating *every* uuid in a copied playbook, which rewrites the step types
too. When copying a playbook, replace only its own ids: collection, workflow,
steps and routes (pitfall 36).

**2.2 Step names use only letters, digits, underscores and spaces: ERROR.**
A hyphen, slash, bracket or dot breaks the Jinja reference to that step.

**2.3 `triggerStep` matches a step: ERROR.** `triggerStep` is
`/api/3/workflow_steps/<uuid>` of a step that exists in the same workflow.

**2.4 Code Snippet and Connector steps carry the full envelope: ERROR.**
Every Connector or Code Snippet step needs non-empty `connector`, `operation`
and `version`, and a `config` key. An empty `config` value is allowed (see 7.2),
a missing key is not. A Code Snippet with only `params.python_function` fails
with "retrieving the connector operation None".

**2.5 Code Snippet identity: ERROR.** On a Code Snippet step, `connector` is
`code-snippet` and `operation` is `python_inline_code_editor`.

**2.6 Step type matches the argument shape: ERROR.** A step whose `arguments`
contain both `query` and `module` must be Find Records (`...928770`). Under the
Update Record type (`...928722`, two digits away) it is a write step.

## 3. Layout on the canvas

The designer grid, verified on a live appliance:

- `top` and `left` are **strings**.
- `left = 125 + 175 × column` (125, 300, 475, 650, ...).
- `top = 30 + 135 × row` (30, 165, 300, 435, ...).

**3.1 `top` / `left` are strings on the grid: WARN when built from scratch.**
Check that `(left - 125)` divides by 175 and `(top - 30)` divides by 135.
Uploaded exports that were laid out by hand keep their positions.

**3.2 No two steps share a position: ERROR when built from scratch, WARN on an export.**
Two steps with the same `top` and `left` sit on top of each other and the
playbook is unreadable in the designer. On an uploaded export, also report two
steps closer than one grid cell (less than 135 apart vertically *and* less than
175 apart horizontally).

**3.3 The main flow runs down one column: WARN when built from scratch (reading check).**
One row per step in execution order. Branches and error or result steps go in
columns to the right. When you insert steps, move every step below them down by
135 per added row so nothing collides.

## 4. Routes and flow

**4.1 Every route points at real steps: ERROR.** The last segment of each
route's `sourceStep` and `targetStep` is the uuid of a step in the same workflow.

**4.2 No cycles: ERROR.** No route may lead back to a step that already ran.
Follow the routes from `triggerStep` and check you never reach a step twice on
one path. For retries or polling, use a step's `do_until` or a `for_each` loop
instead of a route back.

**4.3 No dead ends: WARN.** Every step has an outgoing route unless it is
terminal. Terminal means any of:
- a Set Variable step with incoming routes (a result contract);
- a step whose name contains "result";
- a `no_op` step;
- a step whose arguments carry a `Result` key or a sub-playbook `arguments` block.

A step with neither incoming nor outgoing routes whose name or description says
"spare", "placeholder" or "dummy" is INFO instead: mention it on delivery.

**4.4 Every Decision condition has its route: ERROR.** For each
`arguments.conditions[]` entry, the `step_iri` names an existing step, and a
route exists with the Decision as source and that step as target. The condition
and the route encode the same edge; one without the other is a broken branch.

**4.5 A step where branches converge reads only steps that ran on every branch: WARN (reading check).**
A step reached from exclusive branches runs after whichever branch was taken,
and on that run the other branch's steps did not run (see 5.6).

## 5. Jinja

Collect every string under `arguments` that contains `{{` or `{%`, including
the full source of every code snippet, which FortiSOAR renders as a template.

**5.1 Every template parses: ERROR.** Check that each `{{` has its `}}`, each
`{%` its `%}`, each `{% for %}` / `{% if %}` its `{% endfor %}` / `{% endif %}`,
and that brackets, parentheses and quotes balance inside every expression. The
classic failure is an unparenthesised filter chain:
`(x | default({}, true)).data | default({}, true).IP` does not parse. Wrap each
filtered value in parentheses before reading an attribute from it.

**5.2 Every `vars.steps.<Ref>` resolves: ERROR.** A step's reference is its name
with every non-word character, including each space, replaced by `_`.
`Get Oldest Blocked IPs` is `vars.steps.Get_Oldest_Blocked_IPs`. Search the whole
workflow for `vars.steps.` and check each name against that list.
- If a reference is the start of a real reference followed by `_`, it was cut
  short at a space: write the full underscored name.
- A reference that matches nothing resolves to nothing, without an error.

**5.3 Find Records output has no `.data`: ERROR.** A Find Records step returns
the list itself at `vars.steps.<Name>`. `vars.steps.<Name>.data` resolves to
nothing, and a `| default([])` beside it turns that into a silent empty batch.
This also applies to the guarded form `(vars.steps.X | default({}, true)).data`.

**5.4 Step variables reference real steps: ERROR.** In every `step_variables`
dict, any `vars.steps.<name>` names a step of this workflow. Compare names with
spaces replaced by underscores.

**5.5 `vars.result` only where it means something: WARN.** `vars.result` is a
connector step's own output, inside that step's `step_variables`. In a Code
Snippet's code, or a step variable of a non-connector step, read
`vars.steps.<Name>` instead.

**5.6 A step variable that reads a different step: WARN.** On a Code Snippet,
a step variable that reads some other step's output is usually a cloned step
nobody updated. Keep it only if it is deliberate.

**5.7 Every Configuration value is read: WARN.** For each key a Set Variable
step sets (ignoring the control keys `step_variables`, `when`, `for_each`,
`ignore_errors`, `mock_result`, `message`, `__recommend`, `_showJson`), search
the workflow for `vars.<key>`. No hit means the value is dead: the user edits
it and nothing changes. Also check the code does not hardcode the same value.
- Exempt: the final result step (no outgoing route), and placeholder steps.

## 6. Code snippets

For every step with `params.python_function`:

**6.1 No banned builtins: ERROR.** The sandbox rejects calls to `set`, `any`,
`all`, `enumerate`, `sum`, `type`, `eval`, `exec`, `open`, `reversed`, `map`,
`filter`, `max` and `min`. Only a call counts. The same word in a comment,
string or identifier, or as a method (`x.set(`), is fine.
- Allowed: `list`, `dict`, `tuple`, `str`, `int`, `float`, `bool`, `len`,
  `sorted`, `zip`, `abs`, `round`, `isinstance`, `range` and `print`.
- Replacements:
  - a counter loop for `sum`;
  - an explicit comparison loop for `max` / `min`;
  - a dict of seen keys for `set`;
  - a manual index for `enumerate`.

**6.2 No `lambda`: ERROR.** Write an explicit loop, or an insertion sort with a
key function defined by `def`.

**6.3 No bare `isinstance(x, list)`: WARN.** It raises on some sandboxes, where
`list` is a shim. Bind `LIST_T = builtins.list` once and use
`isinstance(x, LIST_T)`, or branch on `isinstance(x, dict)` first.

**6.4 JSON aliases when Jinja is injected: WARN.** A snippet that contains `{{`
also defines `true, false, null = True, False, None` near the top, so injected
JSON literals evaluate.

**6.5 Exactly one `print()`: WARN.** Count real `print(` calls, not ones inside
comments or strings. There must be one, and it is the last line,
`print(json.dumps(...))`, because only that line is read downstream. None means
no output; more than one means the earlier output is lost.

**6.6 No `{{ vars.result }}` inside code: WARN.** Read other steps as
`vars.steps.<Name>`.

**6.7 `urlencode` is decoded with `unquote_plus`: WARN.** FortiSOAR's `urlencode`
turns a space into `+`. `json.loads(unquote("{{ x | tojson | urlencode }}"))`
fails at the first space. Use `urllib.parse.unquote_plus` (pitfall 43).

**6.8 No whole record or `sourcedata` rendered into the code: WARN.** A pattern
like `{{ vars.input.records[0] }}` or `{{ vars.input.records[0].sourcedata }}`
can exceed the request size; a 2.3 MB alert failed with a bare 500. Build a
trimmed dict in Jinja and pass only the fields the code reads (pitfall 33).

**6.9 Keys read match keys built: ERROR.** When a Jinja `{% for %}` loop builds
dict literals, list the keys it writes (`"key":`). Then list the keys the
Python reads with `x['key']`, outside the `{{ }}` / `{% %}` regions. A key that
is read but never built (or assigned elsewhere) is a KeyError at run time.
Prefer `.get(key, default)` (pitfall 30).

**6.10 Coverage figures have a real denominator: WARN.** A report line such as
"examined X of Y available" must not take Y from `len(rows)` of the same page:
Find Records returns no population count, so it always reads "N of N"
(pitfall 32).

**6.11 Parallel `for_each` results joined on an echoed value: ERROR / WARN.**
A connector `for_each` with `parallel: true` returns results in completion
order.
- ERROR: a snippet reads those results by position (`[i]`, `[idx]`, `[n]`).
- WARN: any snippet that reads them at all. Confirm it joins on a value the
  response echoes back, such as `ipAddress`, or set `parallel: false`
  (pitfall 23).

**6.12 FortiSIEM query strings are well formed: ERROR / WARN.** For every
`cond`, whether inline on a connector step or built in a snippet's query plan:
- ERROR:
  - parentheses balance;
  - double quotes are even in number;
  - no backslash sits right before a closing quote. A string that never ends is
    rejected with a 400.
- WARN, on an inline connector `cond` only (in Python source a doubled backslash
  renders to one):
  - a doubled backslash, which usually matches nothing;
  - a condition with no `customer` scope, which searches every tenant.
- Read the **rendered** query strings, not the code that builds them. Escaping
  bugs only show in the output.

## 7. Connector steps

**7.1 Config, version present: ERROR / WARN.** A step with `connector` and
`name` has a `config` key (ERROR if missing) and a `version` (WARN if empty).
- A config that still holds a placeholder such as `<SELECT ...>` is a WARN: ask
  the user for the real uuid.

**7.2 Empty config: INFO.** `""` means "this instance's default configuration".
It is portable, and right for lookups and utilities. It is never right for a
response connector on a multi-tenant instance, where the config selects the
client's device (`connector-configs.md`).

**7.3 Enrichment loops do not abort the run: WARN.** Set `ignore_errors: true`
on every lookup step (FortiGuard, VirusTotal, AbuseIPDB, WHOIS, sandbox, threat
intel and so on) and on every connector step that runs a `for_each`. Leave it
unset only where a failure genuinely must stop the playbook.

**7.4 Independent lookups fan out: WARN.** Look at two connector steps where
the first routes straight into the second. If they loop over the same list, or
the second never reads `vars.steps.<first>`, they are independent: route both
from their shared parent and converge on the next step.

**7.5 No empty `for_each`: ERROR.** A `for_each` whose `item` is empty fails
with CS-WF-3. Delete the whole key on steps that do not loop.

**7.6 Sub-playbook arguments match the child: ERROR / WARN.** For each
Reference-a-Playbook step whose target is in the same file, compare the keys of
`arguments.arguments` with the child's `parameters`.
- ERROR: a key the child does not declare. The child receives nothing for it
  and still succeeds.
- WARN: a declared parameter that is not passed.
- Argument names differ between clients (`DomianList` vs `Domain_List`), so
  copy them from the child (pitfall 37).

**7.7 Copied manual inputs have no stale `parentstepid`: WARN.** A Manual Input
whose `message.parentstepid` points at a step not in this playbook was copied
from another one. Remove the key; FortiSOAR sets it on import.

## 8. Find Records and queries

**8.1 Page size lives in the module string: ERROR / WARN.** A Find Records step
returns 30 rows unless its `module` string carries `?$limit=N`.
- ERROR: it sets `query.limit` to something other than 30 without `$limit` in
  the module. The limit is ignored.
- WARN: it has no `$limit` at all. State the size where it is read (pitfall 31).

**8.2 `query.limit` is an integer: ERROR.** A Jinja string there is ignored and
the query returns the 30-row ceiling.

**8.3 Date filters use ISO strings: ERROR.** A filter on a field whose name
contains `date` or `time` must not have a number, a numeric string, or an
expression with `timestamp()`, `epoch` or `.now()` as its value. The query API
returns a DriverException 400. Use `"2026-08-01"`, and end bounds with
`lt <next day>` (pitfall 29).

## 9. Manual inputs and substance

These fire only where they apply, so a simple reporting playbook is not nagged.
They exist because a playbook can pass every check above and still tell an
analyst nothing.

**9.1 Enrichment reaches a verdict: WARN.** If the playbook runs lookups and
has code, the code assigns a verdict, classification, disposition or
assessment, and records the reason for it.

**9.2 Manual input bodies are readable reports: WARN.**
- The input's `schema.description` is HTML, not Markdown (`**bold**` shows as
  literal asterisks).
- It renders a table, a loop or HTML built upstream, not a static blurb or a
  raw dump.

**9.3 A manual input is guarded by a Decision: WARN.** If there is a Manual
Input but no Decision step, an empty batch asks the analyst to review nothing.
Give the empty path its own route to the result step.

## 10. Counts to report

**10.1 Code snippet count: INFO.** Report how many Code Snippet steps each
workflow has. Native steps survive sandbox upgrades better (`conventions.md`,
"Native step or Code Snippet?").

**10.2 Default configs: INFO.** List the steps that use an empty config (7.2).

---

## What this checklist cannot catch

It checks wiring, not behaviour. After it passes, still:

- **Run each code snippet** with representative input if you can execute code:
  substitute the Jinja with sample data and run it. A snippet that raises fails
  the step with no traceback.
- **Read the generated query strings** as they will be sent.
- **Write and run the test matrix** (`SKILL.md` step 6, `no-access-checklist.md`):
  one scenario per verdict path, including the empty and malformed inputs.
- **Walk each requirement end to end**: name the step that reads each setting
  and produces each output (`no-access-checklist.md`).
