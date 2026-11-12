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

### Option C — skills CLI

```bash
npx skills add git-Jimit/fortisoar-playbook-builder
```

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

The skill works without them: it carries the same checks and methods as written
instructions. With Claude Code and the tools cloned, Claude can also run the
validator for a mechanical second check.

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
