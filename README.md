# FortiSOAR Playbook Builder — Claude Skill

A Claude skill that builds, modifies and reviews **FortiSOAR playbooks** as
complete, importable JSON exports — alert triage, incident response,
investigations, IOC enrichment, phishing analysis, threat hunting,
FortiSIEM / FortiAnalyzer queries, response actions, client approval links and
PDF / HTML / Excel / CSV reports.

Every rule in it was written after a real failure on a FortiSOAR appliance, and
each mechanical one is a step in its validation checklist.

It follows the open Agent Skills format, so it also works in other agents that
read that format, such as ChatGPT / Codex, Cursor, VS Code and Gemini CLI. It
was built and tested on Claude.

> Not affiliated with or endorsed by Fortinet. FortiSOAR, FortiSIEM and
> FortiAnalyzer are trademarks of Fortinet, Inc.

## Install

### Option A — Claude Code plugin (recommended)

In Claude Code's plugin manager, add this repository (`git-Jimit/fortisoar-playbook-builder`)
as a marketplace and install the `fortisoar-playbook-builder` plugin from the
`fortisoar-skills` marketplace. The exact steps are on the
[project website](https://git-jimit.github.io/fortisoar-playbook-builder-site/#install) and in Claude Code's plugin documentation.

### Option B — Manual (copy the folder)

Download the [latest release](https://github.com/git-Jimit/fortisoar-playbook-builder/releases/latest),
unzip it, and copy its `skills/fortisoar-playbook-builder` folder to one of:

- `~/.claude/skills/fortisoar-playbook-builder/` → personal (all your projects)
- `<project>/.claude/skills/fortisoar-playbook-builder/` → project-scoped

Claude Code auto-discovers the skill from `SKILL.md` on the next session.

### Option C — other agents (skills CLI)

The open [skills](https://skills.sh) CLI can install it into Claude Code or other
Agent Skills agents. Follow the install steps on the
[project website](https://git-jimit.github.io/fortisoar-playbook-builder-site/#install).

### Option D — Claude.ai / Claude desktop

Zip the `skills/fortisoar-playbook-builder` folder and upload it under
**Customize → Skills → Upload skill**.

## Usage

Just describe what you need, e.g.:

> Build a FortiSOAR playbook that runs on alert create, enriches every IP with
> FortiGuard and VirusTotal, and closes the alert as false positive if all are clean.

See [`skills/fortisoar-playbook-builder/README.md`](skills/fortisoar-playbook-builder/README.md)
for what is inside and how to give it good inputs.

## Optional tools

The skill contains only instructions and reference files. Three optional
programs live in a separate repository,
[fortisoar-playbook-tools](https://github.com/git-Jimit/fortisoar-playbook-tools):

| Tool | What it does |
|---|---|
| `validate_playbook.py` | Runs the skill's validation checklist mechanically on any playbook export |
| `extract_connector_configs.py` | Lists the connector configs, versions, picklists and sub-playbooks in an export |
| `pdf_report_engine.py` | A sandbox-safe PDF engine to paste into a FortiSOAR Code Snippet step |

The skill does not use them: it carries the same checks and methods as written
instructions. Each tool's own README says how to install and use it.

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
        ├── README.md
        ├── reference/            # schema, step types, pitfalls, validation checklist
        └── examples/
```

## License

Licensed under the **MIT License** — see [`LICENSE`](LICENSE). © 2026 Jimit Patel.
