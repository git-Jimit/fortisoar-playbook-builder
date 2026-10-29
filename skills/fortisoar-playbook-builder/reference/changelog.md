# Changelog

Newest first. Each entry records what was measured, not only what changed.

## 1.1.1 — directory review fixes (2026-10-29)

- Plain-text wording where the directory scan read a file path or command as
  something the plugin runs. No change to how the skill behaves.

## 1.1.0 — public release cleanup (2026-10-29)

- Examples carry no instance-specific values: the FortiSIEM sample's collection
  is now "FortiSIEM Event Search", and its FortiSIEM and code-snippet steps,
  like the reference playbook's two code-snippet steps, use the empty config
  (the instance's default). AbuseIPDB and FortiGuard keep the defaults listed in
  `connector-configs.md`. Validator results are unchanged: 0 / 0, 2 and 12
  warnings.
- `step-types.md` §8: the code-snippet example uses the empty config instead of
  one instance's uuid.
- `assets/pdf_report_engine.py`: the report time zone is set by
  `REPORT_UTC_OFFSET_MINUTES` and `REPORT_TZ_LABEL` (default UTC) instead of a
  hard-coded UTC+05:30.
- This changelog: the pre-release history is summarised below. Every rule it
  recorded is already in `pitfalls.md`, the other reference files or the
  validator.

## 1.0.1 — directory readiness (2026-10-29)

- Added a plugin icon for the directory listing.
- Split `fortisiem_event_attributes.csv` into `fortisiem_event_attributes_1.csv`
  and `_2.csv` so every file stays under the plugin directory's 256 KiB limit.
  Content is unchanged: 7,030 attribute rows in total.

## 1.0.0 — first public release (2026-10-29)

First public release, published as a Claude Code plugin under the MIT License.
The content is the result of the development history below, validated on a
FortiSOAR 8.0.0 lab appliance and several production installations.

## Development history (before 1.0.0)

The skill went through about twenty internal builds before release. Each round
built real playbooks with it — blocked-indicator revalidation, phishing
analysis, a scheduled housekeeping report, failed-login and IPS triage, alert
backlog sweeps, FortiSIEM enrichment and response, ransomware and endpoint
investigations — ran them on a lab appliance or production instances, and
turned every failure into a pitfall, a reference correction or a validator
check. In outline:

- **Running beats reading.** The most damaging defects passed every static
  check and were found only by executing the playbook: parallel `for_each`
  results joined by index attached 6 of 10 enrichments to the wrong indicator
  (pitfall 23); an empty `for_each` stub killed three generated playbooks on
  their third step (pitfall 22); Find Records read with `.data` returned nothing
  and the run finished green (pitfall 24); a string `query.limit` was ignored
  and a sweep covered 30 of 550 alerts while reporting full coverage (pitfalls
  25, 31, 32).
- **Every defect that got fixed had a validator check behind it; every defect
  that survived was documented in prose only.** Hence the delivery bar of
  0 errors and 0 warnings, and a validator that grew to cover step-reference
  resolution, unread Configuration keys, fan-out vs chaining, `ignore_errors`,
  date filters, canvas overlap, unknown step types, sub-playbook argument names,
  oversized snippet inputs and Jinja syntax in every argument.
- **Measured, not assumed.** The code-snippet sandbox's banned builtins were
  measured call by call (and corrected in both directions); connector versions
  were shown not to be enforced while config uuids are; FortiGuard's config
  uuid held on every instance seen while code-snippet, FortiSIEM and VirusTotal
  configs vary.
- **Validated against production.** Four rules that were right on the lab but
  wrong on production (`isinstance`, `vars.result` in a step's own variables,
  underscore step references, canvas overlap on hand-laid exports) were relaxed
  after running the validator over playbooks that demonstrably run in
  production.
- **Useful, not merely valid.** A canonical reference playbook verified end to
  end against known-correct answers, the "what finished means" table, and
  substance checks for enrichment without verdicts and analyst views that dump
  raw JSON.
- **Portable by default.** An empty connector config means the instance's
  default, so lookups and utilities import anywhere; response connectors on
  multi-client instances are never defaulted.
- **Native steps first.** Upgrades have tightened the code-snippet sandbox
  between versions, so Jinja and native steps are preferred and snippets are
  kept few and plain.
