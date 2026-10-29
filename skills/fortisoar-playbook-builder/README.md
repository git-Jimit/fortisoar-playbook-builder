# FortiSOAR Playbook Builder

An agent skill that builds, modifies and reviews **FortiSOAR playbooks** as
complete, importable JSON exports — alert triage, incident response,
investigations, IOC enrichment, phishing analysis, threat hunting,
FortiSIEM / FortiAnalyzer queries, response actions, client approval links and
PDF / HTML reports.

Author: **Jimit Patel** · Version 1.1.1 · See `reference/changelog.md` for history.

## Why it exists

A generated FortiSOAR playbook usually fails in one of two quiet ways: it
imports and then does nothing (a reference that resolves to empty, a loop over
an empty list, a field the parser never fills), or it runs and tells the analyst
nothing useful. Every rule in this skill was written after one of those
happened on a real appliance, and most are enforced by the bundled validator.

## What is inside

| Path | Purpose |
|---|---|
| `SKILL.md` | The instructions the agent follows — start here |
| `reference/` | Schema, step types, conventions, triggers, connector behaviour (FortiGuard, VirusTotal, CrowdStrike, FortiSIEM, email ingestion, WinRM), 44 documented pitfalls, reports |
| `scripts/validate_playbook.py` | Static validator for any playbook export |
| `scripts/extract_connector_configs.py` | Harvests connector config uuids from an export of your instance |
| `assets/pdf_report_engine.py` | Sandbox-safe PDF drawing for code-snippet steps |
| `examples/` | A verified reference playbook and two real-world samples |

## Using the validator on its own

It needs only Python 3 and works on any FortiSOAR playbook export, generated or
hand-built:

```
python3 scripts/validate_playbook.py my_playbook_export.json
```

It exits non-zero on errors. **ERROR** means the playbook will fail or silently
do nothing; **WARN** means it will run but something will hurt at run time;
**INFO** marks an accepted exception such as an unattached spare step. Exports
made by hand in the FortiSOAR designer commonly show warnings — use them as a
review list.

## Give it good inputs

The skill works best when you provide, up front:

1. How the playbook should start (manual, on create/update, schedule, API, sub-playbook).
2. One real `sourcedata` sample from the module it runs on.
3. Any playbook export from **your** FortiSOAR that uses the connectors involved —
   connector config ids differ between installations.
4. On a multi-tenant instance, which client the playbook is for.

Without these it still builds, states its assumptions and tells you exactly
what to confirm after import.

## Compatibility notes

Behaviour was measured on a FortiSOAR 8.0.0 lab appliance and on several production installations. Some
details — notably the code-snippet sandbox's restrictions and connector config
ids — differ between installations; the skill writes portable code by default
and flags instance-specific values for you to confirm.
