# FortiSOAR Playbook Builder — Claude Skill

A Claude skill that builds, modifies and reviews **FortiSOAR playbooks** as
complete, importable JSON exports — alert triage, incident response,
investigations, IOC enrichment, phishing analysis, threat hunting,
FortiSIEM / FortiAnalyzer queries, response actions, client approval links and
PDF / HTML reports.

Every rule in it was written after a real failure on a FortiSOAR appliance, and
most are enforced by the bundled static validator.

> Not affiliated with or endorsed by Fortinet. FortiSOAR, FortiSIEM and
> FortiAnalyzer are trademarks of Fortinet, Inc.

## Install

### Option A — Claude Code plugin (recommended)

Inside Claude Code:

```
/plugin marketplace add git-Jimit/fortisoar-playbook-builder
/plugin install fortisoar-playbook-builder@fortisoar-skills
```

Or from the terminal:

```bash
claude plugin marketplace add git-Jimit/fortisoar-playbook-builder
claude plugin install fortisoar-playbook-builder@fortisoar-skills
```

### Option B — Manual (copy the folder)

```bash
git clone https://github.com/git-Jimit/fortisoar-playbook-builder.git
cp -r fortisoar-playbook-builder/skills/fortisoar-playbook-builder ~/.claude/skills/
```

- `~/.claude/skills/fortisoar-playbook-builder/` → personal (all your projects)
- `<project>/.claude/skills/fortisoar-playbook-builder/` → project-scoped

Claude Code auto-discovers the skill from `SKILL.md` on the next session.

### Option C — Claude.ai / Claude desktop

Zip the `skills/fortisoar-playbook-builder` folder and upload it under
**Customize → Skills → Upload skill**.

## Usage

Just describe what you need, e.g.:

> Build a FortiSOAR playbook that runs on alert create, enriches every IP with
> FortiGuard and VirusTotal, and closes the alert as false positive if all are clean.

The validator also works standalone on any playbook export:

```bash
python3 skills/fortisoar-playbook-builder/scripts/validate_playbook.py my_playbook.json
```

See [`skills/fortisoar-playbook-builder/README.md`](skills/fortisoar-playbook-builder/README.md)
for what is inside and how to give it good inputs.

## What the bundled scripts do

`validate_playbook.py` and `extract_connector_configs.py` only read the export
file you pass them and print to the terminal. They make no network calls, read
no credentials or environment variables, and install nothing (the validator
uses `jinja2` for its syntax check if it is already installed).

`assets/pdf_report_engine.py` is not run locally: it is source you paste into a
FortiSOAR Code Snippet step, where it uploads the PDF it draws to that same
FortiSOAR as an attachment.

## Layout

```
.
├── README.md
├── LICENSE
├── .claude-plugin/
│   ├── marketplace.json        # makes this repo a plugin marketplace
│   └── plugin.json             # the plugin (lives at the repo root)
└── skills/
    └── fortisoar-playbook-builder/   # the skill (copy THIS for manual install)
        ├── SKILL.md
        ├── reference/
        ├── scripts/
        ├── assets/
        └── examples/
```

## License

Licensed under the **MIT License** — see [`LICENSE`](LICENSE). © 2026 Jimit Patel.
