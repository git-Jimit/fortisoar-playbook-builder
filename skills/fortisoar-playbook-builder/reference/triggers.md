# Triggers — decide this first, because it decides everything else

The trigger determines **where input arrives**, **whether a record exists at
all**, whether the playbook can be tested over HTTP, and how many times it runs
when several records are selected. Choosing it after writing the steps means
rewriting every variable reference.

Ask the user, in these words, before designing anything:

> **How should this playbook start?**
> - An analyst selects one or more records and clicks Execute
> - Automatically, whenever a record is created (or updated)
> - On a schedule — every N minutes/hours, with no record involved
> - Called by another playbook, with parameters
> - Over HTTP, from something outside FortiSOAR
>
> **And what does it run on?** A single record, a batch the analyst selected, or
> nothing at all (it goes and finds its own data)?

---

## The five triggers

Distribution across 120 real playbooks on a production appliance, so you can see
what is actually normal:

| Trigger | stepType uuid | Count | Input arrives as |
|---|---|---|---|
| **Manual on records** `cybersponse.action` | `f414d039-bb0d-4e59-9c39-a8f1e880b18a` | 62 | `{{vars.input.records[0]}}` |
| **Referenced / Scheduled** `cybersponse.abstract_trigger` | `b348f017-9a94-471f-87f8-ce88b6a7ad62` | 44 | `{{vars.input.params['<name>']}}` |
| **On update** `cybersponse.post_update` | `9300bf69-5063-486d-b3a6-47eb9da24872` | 7 | `{{vars.input.records[0]}}` |
| **On create** `cybersponse.post_create` | `ea155646-3821-4542-9702-b246da430a8d` | 6 | `{{vars.input.records[0]}}` |
| **API route** `cybersponse.api_call` | `df26c7a2-4166-4ca5-91e5-548e24c01b5f` | 1 | `{{vars.input.params.api_body.<name>}}` |

Confirmed `step_variables` from live playbooks:

```
action        {"input": {"records": "{{vars.input.records[0]}}"}}
post_create   {"input": {"params": [], "records": ["{{vars.input.records[0]}}"]}}
abstract      {"input": {"params": {"queryURL": "{{ vars.queryURL }}", ...}}}
api_call      {"input": {"params": []}}
```

---

## Manual on records — the default

62 of 120. An Execute button on the record's action menu.

```json
{"route": "<uuid>", "resources": ["alerts"], "__triggerLimit": true,
 "executeButtonText": "Run IR Response",
 "displayConditions": {"alerts": {"logic": "AND", "filters": [], "limit": 30}},
 "noRecordExecution": false, "singleRecordExecution": true,
 "step_variables": {"input": {"params": [], "records": "{{vars.input.records}}"}}}
```

- `resources` — which module's action menu it appears on
- `displayConditions` — filters that decide when the button is shown
- `executeButtonText` — the button label; write a real verb
- `singleRecordExecution` — `true` runs once per selected record, `false` runs
  once with the whole selection. Decide deliberately: a report per alert wants
  `true`, a digest across alerts wants `false`
- `noRecordExecution` — `true` if it can run with nothing selected (40 of 62 do)

**It has no HTTP route.** The `route` field is ignored; FortiSOAR answers
`No active workflow matching the given route`. This trigger can only be fired
from the GUI. To test one programmatically, import a temporary copy with an
`api_call` trigger, drive that, then delete the copy — see *Testing* below.

## Referenced / Scheduled — one step type, two very different jobs

44 of 120. The same `abstract_trigger` covers both, which is why it is the
easiest one to get wrong.

**Called by another playbook** — a `WorkflowReference` step invokes it and
passes named parameters. Declare each one in the workflow's `parameters` array
or it cannot be passed in at all. Read them as
`{{vars.input.params['<name>']}}`.

**Attached to a schedule** — a schedule entry points at the workflow:

```json
{"task": "workflow.tasks.periodic_task",
 "crontab": {"minute": "1", "hour": "1", "day_of_month": "*", "timezone": "UTC"},
 "kwargs": {"wf_iri": "/api/3/workflows/<uuid>", "referenceid": null}}
```

**`referenceid` is null, and the trigger's `step_variables` is
`{"input": {"params": []}}` — a scheduled playbook receives NO RECORD.**

This is the single biggest trap in trigger choice. Every reference to
`vars.input.records[...]` in a scheduled playbook resolves to nothing, silently,
and the playbook completes green having done nothing. A scheduled playbook must
find its own data with a Find Records step or a connector query as its first
real action.

## On create / on update — automatic, and it fires on everything

`post_create` fires for **every** record created in the module, `post_update`
for every update. There is no selection step and no human in the loop.

Two consequences worth stating to the user before choosing it:

- Volume. On a module taking hundreds of alerts a day, this runs hundreds of
  times a day. Every enrichment call is multiplied by that.
- `post_update` can re-trigger itself if the playbook updates the same record.
  Guard it with a `when` condition on the field you are about to change.

### Field-based triggers, and one playbook per client

On an MSSP instance every client's alerts share one module, so an on-create or
on-update trigger with no client condition runs for **all** of them. Observed:
a per-client playbook whose trigger filtered only on `source` and a changed
field — correct for one client, and firing on thirty.

- Put the client in the trigger itself, using the field the alerts carry
  (production example: `organizationName` `eq` `ClientA.org`, or `like` `%ClientB%`).
- `Is Changed` fires on **every** change to that field, not only the first
  write. If an external service might rewrite the field, the playbook runs again
  and repeats its actions — for example sending the client a second IR link.
- Deliver an automatically triggered playbook **inactive**, and say which
  client condition must be added before switching it on.
- Keep per-client copies thin: the trigger condition and the client's settings
  in a Configuration step, with shared logic in one reference sub-playbook.
  Thirty full copies means thirty edits for every change.
- A playbook triggered on create can race an ingestion that finishes enriching
  the record asynchronously; see pitfall 34.

## API route — the only one you can drive over HTTP

1 of 120 in practice, but the one to use when something outside FortiSOAR needs
to start the playbook, and the one to use for testing.

Creating it returns a route; POST to it:

```
POST /api/triggers/1/<route-uuid>
{"alert_iri": "/api/3/alerts/<uuid>", "sourcedata": "..."}
```

Read the body as `{{vars.input.params.api_body.<name>}}`. Declare every name in
the workflow's `parameters` array — an undeclared name cannot be passed.

**An api-triggered playbook only answers on its route while ACTIVE.** Leaving one
active leaves an open route; deactivate it when you are done.

---

## Testing a trigger you cannot fire

Manual, on-create and on-update triggers cannot be driven from a script. To test
one end to end:

1. Import a temporary copy of the playbook with the Start step swapped to
   `cybersponse.api_call` and the Set Case Data step reading from
   `vars.input.params.api_body.*` instead of `vars.input.records[0]`.
2. Seed a record, POST to the twin's route, read the result.
3. Delete the twin.

Everything downstream of Set Case Data is identical, so this exercises the real
logic. Keep the deliverable on its intended trigger — do not ship the API twin.

---

## Choosing

| The user says | Trigger |
|---|---|
| "an analyst runs it on an alert" | Manual on records |
| "when a new phishing report arrives" | On create |
| "every morning" / "every 15 minutes" | Referenced + schedule — **no record** |
| "the other playbook should call this part" | Referenced with parameters |
| "our ticketing system should kick it off" | API route |

When it is genuinely ambiguous, default to **Manual on records** and say so.
It is the most common, it keeps a human in the loop, and it is the easiest to
change later — an automatic trigger that fires on every record is the one that
causes damage before anyone notices.
