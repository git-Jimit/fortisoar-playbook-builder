# WorkflowStep Types Reference

Each step's behavior is determined entirely by its `stepType` uuid. These uuids are **fixed system values** — always reuse them exactly as listed here, never invent new ones.

---


## Contents

The **quick lookup table** of every stepType uuid is at the end.

- 1. Trigger — Alert/Record based (auto-run on matching record)
- 2. Trigger — Manual (user clicks "Execute" in UI)
- 3. Trigger — Manual input params only (no record)
- 3b. Trigger — API/Programmatic (lightweight manual trigger)
- 4. Set Variable
- 5. Decision (branch on conditions)
- 6. Connector Operation (integration call: FortiSIEM, FortiGate, Trend Micro, Zoho, threat intel, etc.)
- 7. Utility Operation (built-in FortiSOAR utilities: file conversion, formatting, etc.)
- 8. Code Snippet (custom Python)
- 9. Query Records (search existing FortiSOAR module records)
- 10. Create/Update Record
- 11. Sub-playbook (call another playbook)
- 12. Wait / Pause
- 13. Approval / Manual Input Request
- 14. Update Existing Record (by direct reference/IRI)
- 15. Send Email
- 16. Trigger — Advanced Field-Based (multi-condition, field-change triggers)
- 17. Create Task
- 19. Approval — Formal (with team assignment & Approve/Reject branching)

## 1. Trigger — Alert/Record based (auto-run on matching record)
`stepType: /api/3/workflow_step_types/ea155646-3821-4542-9702-b246da430a8d`

Use when the playbook should fire automatically whenever a record (usually an alert) matching a filter is created/updated.

```json
{
  "arguments": {
    "resource": "alerts",
    "resources": ["alerts"],
    "__triggerLimit": true,
    "step_variables": {
      "input": { "params": [], "records": ["{{vars.input.records[0]}}"] }
    },
    "triggerOnSource": true,
    "fieldbasedtrigger": {
      "sort": [],
      "limit": 30,
      "logic": "AND",
      "filters": [
        { "type": "primitive", "field": "source", "value": "<source name>", "operator": "eq", "_operator": "eq" }
      ]
    },
    "triggerOnReplicate": false
  }
}
```
Name this step `Start`. Always the `triggerStep` target of the Workflow.

## 2. Trigger — Manual (user clicks "Execute" in UI)
`stepType: /api/3/workflow_step_types/f414d039-bb0d-4e59-9c39-a8f1e880b18a`

Use when the playbook is run on-demand against a selected record, or with no record at all.

```json
{
  "arguments": {
    "route": "<uuid, can be a fresh uuid4>",
    "resources": ["alerts"],
    "__triggerLimit": true,
    "inputVariables": [],
    "step_variables": { "input": { "params": [], "records": "{{vars.input.records}}" } },
    "triggerOnSource": true,
    "displayConditions": { "alerts": { "sort": [], "limit": 30, "logic": "AND", "filters": [] } },
    "executeButtonText": "Execute",
    "noRecordExecution": true,
    "showToasterMessage": { "visible": false, "messageVisible": true },
    "triggerOnReplicate": false,
    "singleRecordExecution": false
  }
}
```
`noRecordExecution: true` lets it run without a source record selected (needed for scheduled/standalone playbooks).

## 3. Trigger — Manual input params only (no record)
`stepType: /api/3/workflow_step_types/b348f017-9a94-471f-87f8-ce88b6a7ad62`

Use for utility/helper playbooks invoked by another playbook (sub-playbook) or a simple input form, not tied to a module record.

```json
{
  "arguments": {
    "__triggerLimit": true,
    "step_variables": { "input": { "params": [] } },
    "triggerOnSource": true,
    "triggerOnReplicate": false
  }
}
```
Add named entries under `step_variables` for each expected input param, e.g. `"alert_id": "{{vars.input.params['alert_id']}}"`.

## 3b. Trigger — API/Programmatic (lightweight manual trigger)
`stepType: /api/3/workflow_step_types/df26c7a2-4166-4ca5-91e5-548e24c01b5f`

A simplified manual-trigger variant seen on playbooks built via API/agent tooling rather than the playbook designer UI. Functionally similar to #2 but without the display/UI-specific fields (`displayConditions`, `executeButtonText`, `showToasterMessage`, etc.).

```json
{
  "arguments": {
    "route": "<uuid4>",
    "title": "<playbook name, repeated here>",
    "resources": ["alerts"],
    "__triggerLimit": true,
    "inputVariables": [],
    "step_variables": { "input": { "params": [] } }
  }
}
```
Prefer the fuller #2 (`f414d039-...`) for anything hand-built through this skill unless the user specifically wants the minimal API-style shape (e.g. replicating agent-generated playbooks).

## 4. Set Variable
`stepType: /api/3/workflow_step_types/04d0cf46-b6a8-42c4-8683-60a7eaa69e8f`

Assign one or more variables directly, no connector call. Used both for simple input capture near the start, and for terminal "SetResult" steps that produce the playbook's final structured output.

```json
{
  "arguments": {
    "Result": "{{ {'status': 'SUCCESS', 'message': '...'} }}"
  }
}
```
Any key name is valid (not just `Result`) — arguments is a flat map of `variable_name: value_or_jinja_expression`. For plain static input capture, values can be plain strings instead of jinja, e.g. `{"host_ip": "", "computer_name": "..."}`.

**Convention:** name terminal "final result" steps `SetResult`, `SetResult_<Reason>`, `SetResult1`, `SetResult2`, etc. per branch outcome — this is the pattern used consistently across real playbooks and makes each branch's terminal state easy to scan.

## 5. Decision (branch on conditions)
`stepType: /api/3/workflow_step_types/12254cf5-5db7-4b1a-8cb1-3af081924b28`

```json
{
  "arguments": {
    "conditions": [
      {
        "option": "<branch label, e.g. 'found'>",
        "step_iri": "/api/3/workflow_steps/<uuid of target step>",
        "condition": "{{ <jinja boolean expression> }}",
        "step_name": "<target step name, for readability>"
      },
      {
        "option": "<default/else branch label>",
        "default": true,
        "step_iri": "/api/3/workflow_steps/<uuid of default target step>",
        "step_name": "<target step name>"
      }
    ],
    "step_variables": []
  }
}
```
- Exactly one condition entry should have `"default": true` and **no** `condition` key — this is the else/fallback branch, evaluated when no other condition matches.
- All other entries require a `condition` jinja expression that evaluates to a boolean.
- Each `step_iri` must have a matching `WorkflowRoute` with the same source/target pair (see playbook-schema.md).
- Common condition patterns seen: length checks (`... | length > 0`), equality (`vars.X != ""`), nested data lookups with `| default(...)` guards to avoid errors on missing keys (see conventions.md for the jinja safety pattern).

## 6. Connector Operation (integration call: FortiSIEM, FortiGate, Trend Micro, Zoho, threat intel, etc.)
`stepType: /api/3/workflow_step_types/0bfed618-0316-11e7-93ae-92361f002671`

This is the step type for **every named integration connector**, including `fortinet-fortisiem`. See `fortisiem-queries.md` for the full FortiSIEM-specific pattern (this is your most common use case).

```json
{
  "arguments": {
    "name": "<Display name of the connector, e.g. 'Fortinet FortiSIEM'>",
    "config": "<SELECT_CONFIG>",
    "params": { "...": "operation-specific parameters..." },
    "version": "<connector version string, e.g. '5.4.3'>",
    "connector": "<connector short name, e.g. 'fortinet-fortisiem'>",
    "operation": "<operation id, e.g. 'run_report'>",
    "operationTitle": "<human-readable operation title>",
    "pickFromTenant": false,
    "step_variables": {}
  }
}
```
- `for_each` — **omit the key** for a single call. To loop, add `"for_each": {"item": "{{vars.query_plan}}", "parallel": false, "condition": ""}`; `vars.item` is then available inside `params` for that iteration. An empty `item` fails at run time with CS-WF-3 (pitfall 22).
- `config` — the connector instance uuid. **Do not default to a placeholder.** Reuse it from a playbook the user uploaded, or ask them for it before generating. A placeholder here is the most common reason a generated playbook is unusable. See conventions.md.
- `version` — must match the connector version installed on their instance; a wrong value is rejected at execution. Read it from an uploaded playbook rather than guessing.
- `step_variables` — a connector step's output is not available downstream unless declared here, as `{"<var>": "{{ vars.steps.<This_Step_Name> }}"}`. With `for_each`, that value is a list, one entry per iteration.
- The output of this step is referenced downstream as `vars.steps.<Step_Name>.data` (or `.data['code_output']` if chained after a code-snippet step that reshapes it).

## 7. Utility Operation (built-in FortiSOAR utilities: file conversion, formatting, etc.)
`stepType: /api/3/workflow_step_types/0109f35d-090b-4a2b-bd8a-94cbc3508562`

Same shape as Connector Operation above, but always `"connector": "cyops_utilities"`. Used for things like `convert_to_json` (CSV/XLS/XML → dict).

```json
{
  "arguments": {
    "params": { "type": "filepath", "file_name": "{{vars.item.filepath}}", "file_type": "CSV" },
    "version": "3.7.0",
    "for_each": { "item": "{{vars.some_list}}", "parallel": false, "condition": "" },
    "connector": "cyops_utilities",
    "operation": "convert_to_json",
    "operationTitle": "Utils: Convert XML, CSV, XLS or XLSX Files to Dictionary",
    "step_variables": []
  }
}
```

## 8. Code Snippet (custom Python)
`stepType: /api/3/workflow_step_types/1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8`

**A Code Snippet is a Connector step underneath.** It needs the full connector
envelope — `connector`, `operation`, `version` and a real `config`. Supplying
only `params.python_function` produces a step that fails the moment it runs:

```
Error occurred while retrieving the connector operation None
ERROR :: Operation matching query does not exist. Connector :: code-snippetV2.2.1
```

An earlier version of this file showed the short form and said the `config`
could be a fresh uuid4. Both were wrong, and a playbook built from it died on
its first code step. Use this instead:

```json
{
  "arguments": {
    "config": "",
    "params": { "python_function": "<python source as a string>" },
    "version": "2.2.1",
    "connector": "code-snippet",
    "operation": "python_inline_code_editor",
    "operationTitle": "Execute Python Code",
    "step_variables": []
  }
}
```

`config` and `version` are instance values — see `connector-configs.md`. An
empty `config` uses the instance's default configuration; otherwise take the
`config_id` from an export of the same instance. The `connector` and
`operation` strings are fixed and always exactly as above.
- The Python runs in FortiSOAR's restricted execution environment. **Must** follow the restrictions in `conventions.md` (no `set()`, `any()`, `min()`, `max()`, `enumerate()` — use listed workarounds).
- The script's return value becomes available downstream as `vars.steps.<Step_Name>.data['code_output']`.
- Access upstream data inside the script via jinja substitution at the top of the script, e.g. `src = {{ vars.sourceData }}` or `data = {{ vars.steps.Some_Step.data }}` — FortiSOAR renders the jinja before executing the Python, so the value gets inlined as a literal.
- For anything containing free text (email bodies, subjects, command lines, alert descriptions) use the robust form `X = json.loads(unquote_plus("{{ v | tojson | urlencode }}"))` with `from urllib.parse import unquote_plus` (pitfall 43), pass a **trimmed** dict rather than a whole record (pitfall 33), and scrub emoji and surrogates before printing (pitfall 44).

## 9. Query Records (search existing FortiSOAR module records)
`stepType: /api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928770`

```json
{
  "arguments": {
    "query": {
      "sort": [],
      "limit": 30,
      "logic": "AND",
      "filters": [
        { "type": "primitive", "field": "name", "value": "...", "operator": "eq", "_operator": "eq" }
      ],
      "__selectFields": ["sourceId", "name", "createDate"]
    },
    "module": "alerts?$limit=30",
    "checkboxFields": true,
    "step_variables": []
  }
}
```
- `module` is the FortiSOAR module API name plus an optional `?$limit=N` suffix.
- Filter `type` can be `primitive` (field/operator/value) or `datetime` (relative/absolute date range, see the `getRelativeDate(...)` helper in conventions.md).
- Result referenced downstream as `vars.steps.<Step_Name>.data` — but see pitfall 24 for when `.data` is absent; read both the wrapped and the bare list.
- **Omit `for_each` entirely unless the step loops.** An empty `item`
  (`"for_each": {"item": "", ...}`) fails at run time with CS-WF-3 and the
  validator rejects it (pitfall 22). This applies to every step type.

## 10. Create/Update Record
`stepType: /api/3/workflow_step_types/2597053c-e718-44b4-8394-4d40fe26d357`

```json
{
  "arguments": {
    "when": "{{ <optional jinja boolean guard, or omit> }}",
    "resource": {
      "name": "<record title, can use jinja>",
      "type": "/api/3/picklists/<uuid>",
      "state": "/api/3/picklists/<uuid>",
      "status": "/api/3/picklists/<uuid>",
      "severity": "/api/3/picklists/<uuid>"
    },
    "operation": "Overwrite",
    "collection": "/api/3/alerts",
    "fieldOperation": [],
    "step_variables": []
  }
}
```
- `collection` is the target module's API path (e.g. `/api/3/alerts`, `/api/3/incidents`).
- Picklist uuids (severity, status, state, type) are **environment-specific** — prefer the portable filter, e.g. `"{{ 'Severity' | picklist('High', '@id') }}"` (`conventions.md`), or flag them as placeholders like connector `config`.
- To create records in a loop, add `"for_each": {"item": "{{ <list> }}", "parallel": false, "condition": "", "__bulk": false, "batch_size": 100}`; omit it otherwise (pitfall 22).
- `operation: "Overwrite"` creates a new record when no matching record id is supplied, or updates the referenced one when it is.

**Adding a comment to an alert** (verified on a lab appliance) — a Create Record on
the comments module, linked through the relationship field:

```json
"resource": {"content": "<p>HTML comment</p>", "alerts": ["{{ vars.input.records[0]['@id'] }}"]},
"operation": "Overwrite",
"collection": "/api/3/comments",
"fieldOperation": []
```

The content is rich text, so HTML tables render. Use `incidents` instead of
`alerts` for an incident.

## 11. Sub-playbook (call another playbook)
`stepType: /api/3/workflow_step_types/74932bdc-b8b6-4d24-88c4-1a4dfbc524f3`

```json
{
  "arguments": {
    "arguments": { "<param_name>": "<value or jinja>" },
    "apply_async": false,
    "ignore_errors": true,
    "step_variables": [],
    "pass_parent_env": false,
    "pass_input_record": false,
    "workflowReference": "/api/3/workflows/<uuid of the target playbook>"
  }
}
```
`workflowReference` uuid is environment-specific (points at an existing playbook already in FortiSOAR) — flag as a placeholder unless the user is providing the target playbook's real uuid.

## 12. Wait / Pause
`stepType: /api/3/workflow_step_types/6832e556-b9c7-497a-babe-feda3bd27dbf`

```json
{
  "arguments": {
    "type": "TimeBased",
    "delay": { "days": 0, "hours": 0, "weeks": 0, "minutes": 0, "seconds": 20 },
    "rule": {
      "is_active": true,
      "entity_name": "Alerts",
      "entity_type": "alerts",
      "event_source": "crudhub",
      "trigger_condition": { "sort": [], "limit": 30, "logic": "AND", "filters": [] },
      "actions": [{ "type": "resume_playbook", "enabled": true, "channel_uuid": "<uuid4>" }]
    },
    "step_variables": []
  }
}
```

**The delay fields accept Jinja** (verified on a lab appliance): to wait until a
point in time — e.g. five minutes after the event, not after the alert arrived —
compute the remaining seconds upstream and pass them in:

```json
"delay": {"days": 0, "hours": 0, "weeks": 0, "minutes": 0,
          "seconds": "{{ vars.steps.Extract.data['code_output']['wait_seconds'] }}"}
```

Floor the value at a few seconds and cap it (hours, not days); an alert processed
late then waits only briefly instead of not at all or forever.

## 13. Approval / Manual Input Request
`stepType: /api/3/workflow_step_types/fc04082a-d7dc-4299-96fb-6837b1baa0fe`

Pauses the playbook and presents a question to a human analyst.

**Two different step types exist. Pick deliberately:**

| | uuid | Buttons |
|---|---|---|
| `ManualInput` | `fc04082a-d7dc-4299-96fb-6837b1baa0fe` | **any labels you want** |
| `ApprovalManualInput` | `a19333c2-c822-11ed-afa1-0242ac120002` | locked to Approve / Reject |

Measured across 50 live steps on an appliance: every `ApprovalManualInput` had
exactly `["Approve", "Reject"]`, while `ManualInput` carried custom sets like
`["Block", "False Positive"]` and `["Unblock Completed", "Unable to Unblock"]`.
If your buttons are anything other than Approve/Reject, use `ManualInput`.

**The buttons are `response_mapping.options`, and each one routes directly.**
There is no separate Decision step — `step_iri` on the option IS the branch:

```json
{
  "type": "InputBased",
  "input": {"schema": {
    "title": "<jinja>",
    "description": "<jinja HTML body; {% for %} loops work>",
    "inputVariables": []
  }},
  "record": "",
  "resources": "s_b_m_blocked_i_ps",
  "is_approval": false,
  "isRecordLinked": false,
  "owner_detail": {"isAssigned": false, "emailRecipients": ""},
  "response_mapping": {
    "options": [
      {"option": "Keep Indicators", "primary": false,
       "step_iri": "/api/3/workflow_steps/<uuid>"},
      {"option": "Remove Clean Indicators", "primary": true,
       "step_iri": "/api/3/workflow_steps/<uuid>"}
    ],
    "duplicateOption": false,
    "customSuccessMessage": "Decision recorded."
  },
  "email_notification": {"enabled": false, "smtpParameters": []},
  "unauthenticated_input": false,
  "step_variables": []
}
```

Each option's `step_iri` still needs a matching **route** as well — the option
alone does not wire the graph.

**The `description` is rendered as HTML — never write markdown in it.**
`**bold**` and `- lists` show as literal characters. Observed: a client said an
IR approval "didn't show details properly" until the body was rebuilt as HTML —
an alert summary table, an indicator table (verdict colour, details, evidence),
an "already handled" table and the list of options. Build tables with jinja
loops. Colours that read on both light and dark themes: header `#1a237e` with
white text; verdicts red `#C62828`, orange `#E65100`, purple `#6A1B9A`, green
`#2E7D32`, grey `#757575`; borders `#999`. The validator warns when a manual-input
description contains `**` and no HTML tag.

`isRecordLinked: false` with `record: ""` is valid and is what you want when the
playbook found its own data rather than being handed a record.

**A manual input cannot be resolved over the API** — see pitfall 20. Any
API-driven test stops here, so the branches below it stay unexecuted.

## 14. Update Existing Record (by direct reference/IRI)
`stepType: /api/3/workflow_step_types/b593663d-7d13-40ce-a3a3-96dece928722`

Distinct from #10 (Create/Update Record). Use this when the playbook already knows exactly *which* record to modify (has its IRI in hand — e.g. closing the incident that triggered the playbook), rather than creating a new record or matching one by a query. Common for terminal "close the case" steps.

```json
{
  "arguments": {
    "resource": {
      "phase": "/api/3/picklists/<uuid>",
      "status": "/api/3/picklists/<uuid>",
      "resDate": "{{globalVars.Current_Date}}",
      "resolution": "{{vars.steps.Some_Comment_Step.content}}",
      "resolveddate": "{{globalVars.Current_Date}}",
      "incidentsummary": "<summary text, can be jinja-templated>"
    },
    "_showJson": true,
    "operation": "Append",
    "collection": "{{vars.input.params['incident_IRI']}}",
    "collectionType": "/api/3/incidents",
    "fieldOperation": { "recordTags": "Append" },
    "step_variables": []
  }
}
```
- `collection` — the **specific record's IRI** (not a module path with `?$limit=`), typically passed in from an upstream step/param.
- `collectionType` — the module API path this record belongs to (`/api/3/incidents`, `/api/3/alerts`, etc.).
- `operation: "Append"` merges into the existing record rather than replacing it wholesale.

**Tags:** `"recordTags": ["enriched"]` with `"fieldOperation": {"recordTags": "Append"}`
adds a tag by name. Measured on a lab appliance: when a **second** Update Record
step on the same run appends another tag, the record ends up with only the
second tag. Write every tag the record should keep in the later step
(`["enriched", "itsm-down"]`), or tag once at the end.

## 15. Send Email
`stepType: /api/3/workflow_step_types/4c0019b2-055c-44d0-968c-678a0c2d762e`

```json
{
  "arguments": {
    "config": "<SELECT_SMTP_CONFIG>",
    "params": {
      "to": "<recipient, jinja allowed>",
      "cc": "",
      "bcc": "",
      "from": "",
      "type": "Manual Input",
      "subject": "<subject line>",
      "content": "<HTML body, jinja allowed>",
      "body_type": "Rich Text",
      "iri_list": "",
      "file_name": "",
      "file_path": ""
    },
    "version": "2.4.3",
    "from_str": "<sender address shown, e.g. soc@example.com>",
    "connector": "smtp",
    "operation": "send_email_new",
    "operationTitle": "Send Email",
    "step_variables": []
  }
}
```

**Sending a generated file (e.g. a PDF report) as an attachment** — verified on a
production instance. A connector step (`0bfed618-…`, see §6) with the SMTP
`send_email` operation and the **attachment IRI** in `iri_list`:

```json
{
  "name": "SMTP", "connector": "smtp", "version": "2.6.0", "config": "",
  "operation": "send_email", "operationTitle": "Send Email",
  "params": {
    "to_recipients": "{{ vars.report_recipients }}", "cc_recipients": "", "bcc_recipients": "",
    "subject": "<subject>",
    "body": "<HTML body>",
    "iri_list": "{{ vars.steps.Build_Report.data['code_output']['attachment_iri'] }}"
  },
  "when": "{{ vars.steps.Build_Report.data['code_output']['attachment_iri'] | string | length > 0 }}",
  "ignore_errors": true, "step_variables": []
}
```

An empty `iri_list` sends the email **without** the file and still succeeds —
the symptom reported was "the email arrives but the report is missing". Guard the
step on the IRI being non-empty, and take the IRI from the code that created the
attachment (`reports.md`). Confirm the operation and version against an export
from the target instance (`connector-configs.md`).

## 16. Trigger — Advanced Field-Based (multi-condition, field-change triggers)
`stepType: /api/3/workflow_step_types/9300bf69-5063-486d-b3a6-47eb9da24872`

A more expressive variant of the standard auto-trigger (#1) — supports array-membership filters (e.g. tag matching) and "field changed to X" conditions, useful for triggers like "an indicator's reputation just changed to Malicious."

```json
{
  "arguments": {
    "resource": "indicators",
    "resources": ["indicators"],
    "step_variables": { "input": { "params": [], "records": ["{{vars.input.records[0]}}"] } },
    "fieldbasedtrigger": {
      "sort": [], "limit": 30, "logic": "AND",
      "filters": [
        {
          "type": "array", "field": "recordTags", "module": "recordTags",
          "value": ["/api/3/tags/<tag uuid>"], "operator": "in_all", "template": "tags"
        },
        {
          "type": "object", "field": "reputation", "operator": "changed",
          "value": "", "_value": { "@id": "", "display": "", "itemValue": "" }
        },
        {
          "type": "object", "field": "reputation", "operator": "eq",
          "value": "/api/3/picklists/<uuid>",
          "_value": { "@id": "/api/3/picklists/<uuid>", "display": "Malicious", "itemValue": "Malicious" }
        }
      ]
    }
  }
}
```
Use `operator: "changed"` paired with an `operator: "eq"` on the same field to express "this field just changed *to* a specific value" — that's the pattern for reputation/status transition triggers.

## 17. Create Task
`stepType: /api/3/workflow_step_types/dc6ac63d-c5a5-472f-9eb4-6b18473a98b8`

Creates a task/hunt record linked to the triggering alert/incident — for hand-off items a human needs to action (e.g. "revoke file permissions").

```json
{
  "arguments": {
    "message": {
      "tenant": "{{vars.input.records[0].tenant['@id']}}",
      "content": "<HTML task instructions>",
      "records": "['{{vars.input.records[0]['@id']}}']"
    },
    "resource": {
      "name": "<task name>",
      "type": "/api/3/picklists/<uuid>",
      "status": "/api/3/picklists/<uuid>",
      "priority": "/api/3/picklists/<uuid>",
      "alerts": "['{{vars.input.records[0]['@id']}}']",
      "dueBy": null, "notes": null, "owners": null, "assets": null, "persons": null
    }
  }
}
```

## 19. Approval — Formal (with team assignment & Approve/Reject branching)
`stepType: /api/3/workflow_step_types/a19333c2-c822-11ed-afa1-0242ac120002`

A more structured alternative to #13 (Approval / InputBased). Use this when the approval needs to be **assigned to a specific team/person** and has clean binary Approve/Reject outcomes wired directly to branch targets, rather than a free-form multi-option jinja form.

```json
{
  "arguments": {
    "type": "InputBased",
    "input": { "schema": { "title": "<approval title>", "description": "<HTML/jinja body>", "inputVariables": [] } },
    "record": "{{ vars.input.records[0][\"@id\"] }}",
    "resources": "alerts",
    "is_approval": true,
    "isRecordLinked": false,
    "owner_detail": {
      "isAssigned": true,
      "assignedToTeam": [{ "iri": "/api/3/teams/<uuid>", "teamname": "<team name>" }],
      "assignedToPerson": [], "assignedToField": null, "emailRecipients": "", "assignedToRecord": false
    },
    "response_mapping": {
      "options": [
        { "option": "Approve", "primary": true, "step_iri": "/api/3/workflow_steps/<uuid>" },
        { "option": "Reject", "primary": false, "step_iri": "/api/3/workflow_steps/<uuid>" }
      ],
      "connecteStepsLength": 2,
      "customSuccessMessage": "Awaiting Playbook resumed successfully."
    },
    "email_notification": { "enabled": false, "smtpParameters": [] },
    "customEmailExternal": false,
    "unauthenticated_input": false
  }
}
```
Each `response_mapping.options[].step_iri` needs a matching route, same as Decision step conditions.

---

## Quick lookup table

| stepType uuid suffix | Purpose |
|---|---|
| `ea155646-...` | Auto trigger on record match |
| `f414d039-...` | Manual trigger, record-based |
| `b348f017-...` | Manual trigger, params only |
| `df26c7a2-...` | API/programmatic trigger (lightweight manual variant) |
| `04d0cf46-...` | Set Variable / SetResult |
| `12254cf5-...` | Decision / branch |
| `0bfed618-...` | Connector operation (FortiSIEM, FortiGate, etc.) |
| `0109f35d-...` | Built-in utility operation (cyops_utilities) |
| `1fdd14cc-...` | Python code snippet |
| `b593663d-...` | Query/search FortiSOAR records |
| `2597053c-...` | Create/update FortiSOAR record |
| `74932bdc-...` | Call sub-playbook |
| `6832e556-...` | Wait/pause |
| `fc04082a-...` | Approval / human input request (free-form) |
| `b593663d-...-928722` | Update existing record by direct IRI reference |
| `4c0019b2-...` | Send email |
| `9300bf69-...` | Advanced field-based trigger (tag/field-change conditions) |
| `dc6ac63d-...` | Create task |
| `a19333c2-...` | Approval — formal, team-assigned, Approve/Reject branching |

**Note:** `b593663d-7d13-40ce-a3a3-96dece928770` (Query Records, #9) and `b593663d-7d13-40ce-a3a3-96dece928722` (Update Existing Record, #14) share the same prefix but are different step types — check the full uuid suffix, not just the prefix, when identifying a step.
