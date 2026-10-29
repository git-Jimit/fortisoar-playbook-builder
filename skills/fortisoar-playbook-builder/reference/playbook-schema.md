# FortiSOAR Playbook JSON Schema Reference

This is the exact structure an importable FortiSOAR playbook export file must have. Every generated playbook JSON must match this shape exactly — FortiSOAR's import will fail or silently corrupt the playbook on structural mismatches.

## Top-level envelope

```json
{
  "type": "workflow_collections",
  "data": [ <WorkflowCollection> ],
  "macros": [],
  "exported_tags": []
}
```

- Always exactly one `WorkflowCollection` in `data` unless the user explicitly asks for multiple grouped playbooks.
- `exported_tags` — leave as `[]` unless the user gives tags.
- `macros` — optional top-level array of **global variables**, available across every playbook in this export via `{{globalVars.<name>}}` (distinct from per-playbook `vars.*`). Only include this key when the playbook genuinely needs an instance-wide constant (e.g. a "demo mode" flag, a shared timestamp helper). Each entry:
  ```json
  { "name": "Current_Date", "value": "{{arrow.utcnow().timestamp}}", "default_value": "{{arrow.utcnow().timestamp}}" }
  ```
  Omit the `macros` key entirely (don't include an empty array) for a typical single-playbook build unless the user is replicating FortiSOAR's out-of-the-box use-case-pack style, which does use this.

## WorkflowCollection object

```json
{
  "@context": "/api/3/contexts/WorkflowCollection",
  "@type": "WorkflowCollection",
  "name": "<Collection / folder name shown in FortiSOAR playbook UI>",
  "description": null,
  "visible": true,
  "image": null,
  "uuid": "<uuid4>",
  "id": null,
  "createDate": null,
  "modifyDate": null,
  "deletedAt": null,
  "importedBy": [],
  "recordTags": [],
  "workflows": [ <Workflow>, ... ]
}
```

- `id`, `createDate`, `modifyDate` — set to `null` for a brand-new collection. Preserve real values as-is if editing an existing uploaded export (see note under Workflow object below).
- `name` — the collection/folder name. Usually matches the playbook's purpose (e.g. "Investigate Failed Logins [FortiSIEM]").
- `workflows` — the array of actual playbooks in this collection. Usually one, unless the user is building a set (e.g. a parent + helper sub-playbooks).

## Workflow object (a single playbook)

```json
{
  "@type": "Workflow",
  "triggerLimit": null,
  "name": "<Descriptive_Playbook_Name>",
  "aliasName": null,
  "tag": null,
  "description": "<what this playbook does, plain language>",
  "isActive": true,
  "debug": true,
  "singleRecordExecution": false,
  "remoteExecutableFlag": false,
  "parameters": [],
  "synchronous": false,
  "lastModifyDate": null,
  "collection": "/api/3/workflow_collections/<same uuid as parent collection>",
  "versions": [],
  "triggerStep": "/api/3/workflow_steps/<uuid of the Start/trigger step>",
  "steps": [ <WorkflowStep>, ... ],
  "routes": [ <WorkflowRoute>, ... ],
  "groups": [],
  "priority": "/api/3/picklists/9e8d41e4-8ada-4a2c-bd02-07f62c6d0a00",
  "playbookOrigin": "/api/3/picklists/15c1e8c9-22bf-4e66-8fbb-0a502d4a4a3f",
  "isEditable": true,
  "uuid": "<uuid4>",
  "id": null,
  "createUser": null,
  "createDate": null,
  "modifyUser": null,
  "modifyDate": null,
  "owners": [],
  "isPrivate": false,
  "deletedAt": null,
  "importedBy": [],
  "recordTags": []
}
```

Key fields to get right:
- `name` — the playbook name shown in the FortiSOAR UI. Use underscores or spaces only, no special characters (see conventions.md). Convention observed: include the source module/connector in brackets, e.g. `Failed Login Investigation [FortiSIEM] (Scheduled)` or `(Manual)`.
- `collection` — must reference the **same uuid** used for the parent `WorkflowCollection.uuid` above, formatted as `/api/3/workflow_collections/<uuid>`. **Exception on uploaded exports:** when FortiSOAR exports a single playbook, the workflow keeps pointing at its original home collection while the file wraps it in a different synthetic collection, so the two uuids won't match. That is normal and imports fine — preserve it rather than rewriting it. The rule above applies to playbooks generated from scratch.
- `triggerStep` — must point to the uuid of whichever step is the Start/trigger step, formatted as `/api/3/workflow_steps/<step uuid>`.
- `parameters` — list of input parameter names if the playbook is designed to take manual input params beyond the base record (rare; usually `[]`).
- `priority` and `playbookOrigin` — always reuse these exact picklist URLs shown above; they are standard FortiSOAR system picklist values seen consistently across all real exports. (`priority` can also be `null` — seen in programmatically/API-created playbooks — but default to the picklist value above for anything hand-authored.)
- `id`, `createUser`, `createDate`, `modifyUser`, `modifyDate` — set to `null` when generating a **brand-new playbook that has never existed in FortiSOAR**. This is the normal case for this skill. Note: a real *export* of a playbook already living on a FortiSOAR instance will have these populated (numeric `id`, real `createUser`/`modifyUser` IRIs, epoch timestamps) — if the user is asking you to **edit an existing playbook** they uploaded, preserve those populated values as-is rather than nulling them out; only null them for genuinely new objects.
- `groups` — visual grouping/notes on the canvas. Leave as `[]` unless the user wants an annotated section; if used, see step-types.md is not relevant — groups use a separate simple object: `{"@type": "WorkflowGroup", "name": "...", "description": "...", "type": "note", "isCollapsed": false, "top":.., "left":.., "width":.., "height":..}`.

## Collection export vs. single-playbook export — there is no format difference

FortiSOAR lets you export **one playbook** or **a whole collection of playbooks** from the UI, and both scenarios produce exactly the same envelope shape described above — `{"type": "workflow_collections", "data": [WorkflowCollection], ...}`. The only difference is how many entries sit in that `WorkflowCollection.workflows[]` array:

- **Single playbook export** → `workflows` has exactly one `Workflow` object.
- **Collection export** → `workflows` has every playbook that belongs to that collection/folder.

When this skill generates a new playbook, default to a single-workflow `workflows` array unless the user explicitly asks for a set of related playbooks bundled into one collection (e.g. a parent investigation playbook plus its sub-playbook helpers) — in which case put all of them in the same `workflows[]` array under one shared `WorkflowCollection`, each with its own `uuid` but all sharing the same `collection` reference.

## WorkflowStep object

```json
{
  "@type": "WorkflowStep",
  "name": "<Step_Name>",
  "description": null,
  "arguments": { ... shape depends on stepType, see step-types.md ... },
  "status": null,
  "top": "280",
  "left": "440",
  "stepType": "/api/3/workflow_step_types/<uuid>",
  "group": null,
  "uuid": "<uuid4>"
}
```

- `top` / `left` — canvas position as **strings**, not numbers. Space steps out left-to-right in the order of execution: increase `left` by roughly 300-400 per step in the main flow, and stagger `top` by ~140-160 for parallel/branch paths so they don't overlap visually. This isn't cosmetic-only — badly overlapping steps make the imported playbook hard for the human to read and edit.
- `name` — must be descriptive of what the step does. Underscores and spaces only (see conventions.md).
- `stepType` — selects which of the ~10 step behaviors this is. See `step-types.md` for the full table and the exact `arguments` shape required for each.

## WorkflowRoute object

Routes are the visual/execution arrows connecting one step to the next. **Every step except the last one(s) in each branch needs an outgoing route**, and decision steps need their `arguments.conditions[].step_iri` to match a real route target too — the route and the decision condition both encode the same edge, so keep them consistent.

```json
{
  "@type": "WorkflowRoute",
  "name": "<SourceStepName> -> <TargetStepName>",
  "targetStep": "/api/3/workflow_steps/<uuid of the next step>",
  "sourceStep": "/api/3/workflow_steps/<uuid of the current step>",
  "label": null,
  "isExecuted": false,
  "group": null,
  "uuid": "<uuid4>"
}
```

- `name` — convention observed: `"<source step name> -> <target step name>"`.
- For a **Decision** step, still create one route per branch, matching each `conditions[].step_iri` target — the route is what actually draws the connecting line; the condition is what actually controls the runtime branch. Both must point to the same target uuid.
- Every step's `uuid` must appear as a `sourceStep` in exactly one route unless it's a terminal step (nothing after it) — dangling steps with no outgoing route are a common import defect. Cross-check this before finalizing output.

## General rules

1. **Every uuid referenced anywhere** (`triggerStep`, `collection`, `stepType` target inside conditions, route `sourceStep`/`targetStep`) must correspond to a uuid actually defined on a real object in the same playbook (or, for `collection`/`stepType`, the fixed system values). Never invent a dangling reference.
2. Generate fresh random uuid4 values for every `WorkflowCollection.uuid`, `Workflow.uuid`, each `WorkflowStep.uuid`, and each `WorkflowRoute.uuid`. Never reuse uuids from example/reference playbooks — those belong to a different FortiSOAR instance and reusing them can cause import collisions.
3. `id`, `createDate`, `modifyDate`, `createUser`, `modifyUser` fields — always `null` in a fresh export. These get populated by FortiSOAR on import.
4. Connector-based steps (see step-types.md) reference a `config` field (a connector configuration instance uuid). This is **environment-specific** — the user's FortiSOAR instance has its own configured connector instances. Leave a clearly-marked placeholder (e.g. `"<SELECT_FORTISIEM_CONFIG>"`) and call this out explicitly to the user after generating the playbook, so they know to pick the right config in the FortiSOAR UI post-import.
