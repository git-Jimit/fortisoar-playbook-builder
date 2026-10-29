# Connector response shapes — parse these by field, never by substring

Every shape below was captured from live calls on a FortiSOAR 8.0.0 appliance.
Each one has a trap that produced a wrong verdict before it was mapped.

---

## FortiGuard Threat Intelligence — `threat_intel_search`

`params: {"indicator": "<ip | domain | hash>"}`

**Clean indicator** (8.8.8.8):

```json
{"wf_cate": "Information Technology", "av_cate": "", "spam_cates": [],
 "ioc_cate": "", "ioc_tags": [], "malware_name": "", "confidence": "Low"}
```

**Malicious indicator** (185.220.101.34):

```json
{"wf_cate": "Malicious Websites", "av_cate": "", "spam_cates": ["Spam Sender"],
 "ioc_cate": "", "ioc_tags": ["Scanner", "Tor", "Bruteforce"],
 "confidence": "Medium"}
```

**Malware hash** (EICAR):

```json
{"wf_cate": "", "av_cate": "EICAR_TEST_FILE", "spam_cates": [],
 "ioc_tags": ["CVE-2023-24860", "AZORult", "Malware"], "confidence": "High"}
```

**Unknown indicator**: `{"message": "Information not found"}`

### Trap 1 — substring matching the serialised reply

Lower-casing the whole response and searching for `"spam"`, `"malicious"` etc.
**matches the schema's own field names.** `spam_cates` is present on every reply,
so every indicator FortiGuard recognises scores a hit.

Measured effect: a clean Google DNS lookup scored a full malicious hit, and a
clean authenticated email graded SUSPICIOUS for no real reason. In production
this would grade nearly everything suspicious and make the playbook useless.

### Trap 2 — reading `malware_name` but not `av_cate`

An antivirus detection is reported in **`av_cate`**, not `malware_name`. A
playbook that only reads `malware_name` scores real malware as clean. EICAR
came back clean this way until `av_cate` was added.

### Correct test

A hit is a **populated field**:

- `wf_cate` in {Malicious Websites, Phishing, Spam URLs, Botnet, Newly Observed
  Domain, Newly Registered Domain}
- `spam_cates` non-empty
- `ioc_tags` non-empty
- `av_cate` non-empty
- `ioc_cate` non-empty
- `malware_name` non-empty

Extract those fields individually in Jinja, then decide in Python. This also
gives per-indicator detail — *"category Malicious Websites; listed as a spam
sender; IOC tags: Scanner, Tor"* instead of a bare boolean.

---

**Low confidence on a major platform is not a block decision.** Observed in
production: `t.me` returned `ioc_tags: ["Malware CnC", "Vidar C2", ...]` with
`confidence: "Low"` — because malware uses Telegram for command and control.
Blocking it would cut off Telegram for the whole client. Route low-confidence
hits on widely used platforms to a human, never to an automatic block.

## VirusTotal — `query_ip`

`params: {"ip": "<ip>", "relationships": ""}`

```json
{"id": "8.8.8.8", "type": "ip_address",
 "attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                        "undetected": 91, "harmless": 0},
                "reputation": 0, "as_owner": "...", "country": "..",
                "whois": {"data": "...multi-line..."}}}
```

`data.id` is the IP. Read `data.attributes.last_analysis_stats`.

### Trap — injecting the whole payload into a code snippet

The reply carries **multi-line whois text**. Rendering the whole object into a
Python snippet breaks the generated source with `invalid syntax`. Inject only
`last_analysis_stats` with a Jinja loop.

---

## VirusTotal — `query_url`

`params: {"url": "<url>", "relationships": ""}`

### Trap — `data.id` is a SHA-1, not the URL

`query_url` identifies a URL by hash, so a report built from `data.id` shows
`3143e0beef9013aa615966ed066428bba186beff` where the analyst expects a domain.
Use `data.attributes.url`, falling back to `data.id`.

---

## VirusTotal — `query_domain` (prefer this for hostnames)

`params: {"domain": "<domain>", "relationships": ""}`

```json
{"id": "example.com",
 "attributes": {"last_analysis_stats": {...},
                "creation_date": 1777700823,
                "registrar": "...", "reputation": 0}}
```

Same cost as `query_url`, and it additionally returns **`creation_date`** — an
epoch you can turn into domain age.

**Domain age catches what reputation misses.** A typosquat registered 8 days
before analysis returned `0/37 engines clean` on VirusTotal and was caught only
by its age. Weight `< 30 days` as strongly as a reputation hit.

---

## VirusTotal — `query_file` (file hashes)

`params: {"file": "<md5 | sha1 | sha256>", "relationships": ""}` —
operation `query_file`, title *Get File Reputation*. **Verified** on a production
instance (connector v3.2.1) in a CrowdStrike triage playbook.

```json
{"data": {"id": "<sha256>", "type": "file",
  "attributes": {"last_analysis_stats": {"malicious": 61, "suspicious": 0, "undetected": 10, "harmless": 0},
                 "last_analysis_results": {"<engine>": {"category": "malicious", "result": "Trojan.Gen"}, ...},
                 "meaningful_name": "...", "names": ["..."], "type_description": "Win32 EXE",
                 "first_submission_date": 1700000000, "size": 12345}}}
```

- A hash VirusTotal has never seen **fails the step** (`NotFoundError`). Put
  `ignore_errors: true` on the loop, and report it as **"Not seen"** — not clean,
  not unknown-malicious. For images and internal documents "not seen" is normal.
- Attribute names beyond `last_analysis_stats` follow the VirusTotal v3 API;
  confirm the ones you read in a first run.

## Trimming VirusTotal results before a code snippet

`last_analysis_results` holds one entry per engine (~90), and domain replies add
whois text. Rendered whole, a handful of lookups can push a code snippet over the
size where it fails with a bare 500 (pitfall 33). Build a trimmed list in jinja,
collecting detection names inside the loop:

```
{% set X = vars.steps.VirusTotal_File_Lookup | default([], true) %}
{% set L = (X.result if (X is mapping and X.result is defined) else X) | default([], true) %}
{% set ns = namespace(o=[]) %}
{% for e in L %}
  {% set dd = (e.data if e is mapping else {}) | default({}, true) %}
  {% set dd = dd.data if (dd.data is defined and dd.data is mapping) else dd %}
  {% set at = dd.attributes | default({}, true) %}
  {% if at.last_analysis_stats is defined %}
    {% set dn = namespace(o=[]) %}
    {% for k, r in (at.last_analysis_results | default({}, true)).items() %}
      {% if r is mapping and r.category == 'malicious' and r.result and dn.o | length < 6 %}{% set dn.o = dn.o + [r.result | string] %}{% endif %}
    {% endfor %}
    {% set ns.o = ns.o + [{'id': dd.id | default('', true), 'stats': at.last_analysis_stats,
                           'creation_date': at.creation_date | default('', true), 'detections': dn.o}] %}
  {% else %}{% set ns.o = ns.o + [{'id': dd.id | default('', true), 'missing': true}] %}{% endif %}
{% endfor %}
{{ ns.o | tojson | urlencode }}
```

Decode it in the snippet with `json.loads(unquote_plus("..."))` (pitfall 43).
Add only the attributes the code reads — for example `as_owner`, `asn`,
`country` for IPs, or `categories`, `title`, `last_final_url` for URLs.
Results stay in input order only with `parallel: false`.

---

## Reading a `for_each` connector step

Each entry is the **full connector envelope**, so the payload is at
`e.data.<field>` — not `e.<field>`.

```
[{% for e in vars.steps.VirusTotal_IP_Check %}
   {"id": "{{ e.data.id | default('') }}",
    "s": {{ e.data.attributes.last_analysis_stats | default({}) }}}
 {% if not loop.last %}, {% endif %}{% endfor %}]
```

And the step itself is read as `{{vars.steps.<Name>}}` with **no `.data`** — the
result is a list, and `.data` on a list is undefined and silently yields
nothing. See `conventions.md`.

**On some instances the list is wrapped.** A production run returned the loop
output as `{"result": [ ...envelopes... ], "status": "finished"}`, not a bare
list. Read it the way that works on both:

```
{% set L = (X.result if (X is mapping and X.result is defined) else X) | default([], true) %}
```

with `X` = `vars.steps.<Name>`. Guard for the payload sitting one level deeper
too (`d.data if d.data is mapping else d`) — it costs nothing.


## Joining fan-out results back to their inputs

`for_each` gives you a list of envelopes, but **the order is only guaranteed
when `parallel` is false**. Prefer joining on a value the connector echoes:

| Connector | Field that echoes the input |
|---|---|
| AbuseIPDB `ip_lookup` | `data.ipAddress` |
| VirusTotal `query_ip` / `query_domain` | `data.id` |
| FortiGuard `threat_intel_search` | `data.reference_url` contains `?query=<indicator>` |

FortiGuard is the awkward one — it echoes the indicator only inside
`reference_url`. If you need a reliable join for FortiGuard, keep its loop
sequential (`parallel: false`) and align by index, which is then safe.

See pitfall 23 for what happens when you get this wrong.


---

## FortiAnalyzer — `start_and_fetch_bulk_device_logs`

Verified by running investigation playbooks against a production FortiAnalyzer.

```json
"params": {"adom_name": "root", "devid": "All_FortiGate", "logtype": "Attack",
           "filter": "srcintf='ssl.VPN' attack!='Some.Signature'",
           "start": "2026-09-10T03:00:00.000Z", "end": "2026-09-10T04:00:00.000Z",
           "limit": 1000, "offset": 0, "time-order": "DESC", "case-sensitive": false,
           "wait_for_search_process_to_complete": true}
```

- Times are ISO UTC with milliseconds and `Z`. In a Set Variable,
  `{{ arrow.utcnow().shift(minutes=-60).isoformat()[:19] }}.000Z` produces one
  whatever arrow's version.
- Filter syntax: `field='value'`, **a space means AND**, `!=` works. Put
  exclusions in the base filter, not in post-processing.
- Rows are at `data.result.data`. **`data.result['total-count']` is the full
  match count even when `limit` caps the rows** — a one-row query gives an exact
  count, and when `total-count > len(rows)` the page was truncated, so say so.
- One high-volume source can fill the whole page and hide everything else. Run
  a second pass that excludes the sources already found.
- `list_log_fields` returns the real field names for a log type. Use it rather
  than guessing (Event/VPN logs carry `remip`, `tunnelip`, `user`, `action`,
  `subtype`; Attack logs carry `srcip`, `srcintf`, `attack`, `dstip`, `action`).
- The connector is read-only for threat data — no block or quarantine action.

**Event Monitor filters (alert ingestion, `Get Event`) are not all filterable.**
Syntax is `field="value"` joined with `and`. `triggername` and `severity` filter;
`eventtype` is present in the data but **silently ignored** as a filter. Before
relying on a field, run a positive control: filter on a value you know occurred
in the window and check that only matching rows come back. A field that is not
filterable returns either everything or nothing — and both look like results.

## FortiDeceptor — `get_attack_events`

A FortiDeceptor connector in production (v1.0.0) returns incident events at
`data.result.events`, with the count at `data.result.total`:

```json
{"time": 1790238014, "event_type": "SSH password attempt", "severity": "Medium Risk",
 "detail": "admin", "username": "admin", "password": "admin"}
```

- `time` is epoch **seconds**.
- **`password` is the attacker's attempted password in clear**, and for some
  event types `detail` repeats it. Never print either into a report, email or
  manual input. Redact `detail` when it equals `password`.
- Incident records carry `attacker_ip` as `"1.2.3.4 (host.example)"`;
  a normalised `fsr_attacker_ip` without the hostname may sit alongside it.

## RichTexttoPDFandEmail — "Email Send"

Observed at version 5.0.4. The operation's internal name is **`sample_delete`**,
titled "Email Send" — it is not a delete.

```json
"params": {"subject": "...", "body": "<p>...</p>", "recipientEmail": "a@b.c",
           "dataForPDF": "{{ vars.steps.Build_Report.data['code_output'] }}",
           "replyToEmail": "", "references": "", "originalSubject": "", "originalMessageID": ""}
```

`dataForPDF` takes the whole code-snippet output, a dict carrying the report's
full HTML document under `html`. Produce the HTML as a complete document with a
`<style>` block and table-based layout; see `reports.md`.

## FSR Utilities — `extract_artifacts_new`

Output keys are `IP`, `URL`, `Domain`, `MD5`, `SHA1`, `SHA256` (plus `Email` and
others depending on input). Parameters used in production:
`private_whitelist: true` (drops RFC1918 addresses), `extract_defang_indicators:
true` (recovers `hxxp://evil[.]com`), and `whitelist` for exclusions. Run it on
analyst- or client-typed text rather than hand-writing regexes.


---

## AbuseIPDB — `ip_lookup`

`params: {"ip": "<ip>", "days": 30}` — the connector, not the raw API. Payload
fields, observed in production: `ipAddress`, `abuseConfidenceScore`,
`totalReports`, `numDistinctUsers`, `countryCode`, `isp`, `usageType`, `domain`,
`hostnames`, `isTor`, `isWhitelisted`, `lastReportedAt`.

**`abuseConfidenceScore: 0` with `totalReports: 0` is not a clean result.** It
means AbuseIPDB has never heard of the address — an absence of evidence
(pitfall 8). Score it as "no data". Only a low score *with* reports, or
`isWhitelisted: true`, is evidence of good behaviour.

`hostnames` can name a scanner outright (`o003.scanner.modat.io`), and
`usageType: "Data Center/Web Hosting/Transit"` with a high score is the usual
signature of an internet scanner or brute-forcer.

---

## CrowdStrike Falcon — triage reads that hold up

Verified on a production instance during a CrowdStrike alert-triage build
(October 2026), unless marked otherwise.

**Has this file run on other hosts? Use ThreatGraph, not Hunt File.**
"Hunt File" needs an API scope many API clients lack, and returned **403**.
ThreatGraph answers the same question through the generic API action:

- connector `crowd-strike-falcon` (v3.2.0 there), operation
  `execute_an_api_request`:

  ```json
  "params": {"method": "GET", "endpoint": "/threatgraph/combined/ran-on/v1",
             "query_params": {"value": "{{vars.item}}", "type": "sha256", "limit": 100},
             "payload": ""}
  ```
- Returns `data.resources[].device_id` for the hosts the file ran on. **A 404
  means "not seen"** — record it as zero hosts, not as an error. Set
  `ignore_errors: true` on the step.
- Requires the **Threatgraph: Read** scope on the API client. If the client
  lacks it, say so in the report ("not checked"), never "0 hosts".
- Cap the count: 100 or more hosts is reported as `100+`.

**Turn device ids into host names** with `device_details` (`ids` = comma list).
Names are at `data.system_info.resources[].hostname` (the shape seen on that
instance; read defensively).

**Was it contained? Read the disposition, not the action name.**
`pattern_disposition_details` / `pattern_disposition_description` describe what
the sensor did. Text containing **"would have"** (e.g. "would have killed the
process") and `policy_disabled` mean **detect-only — nothing was stopped**.
Counting those as contained under-rated a real compromise.

**Never offer a system binary for hash blocking.** A detection's own file is
often `bash`, `powershell.exe`, `cmd.exe`, `rundll32.exe` or — on file-write
detections — the `System` process. Blocking that hash breaks every host.
Exclude system paths (`/bin`, `/usr/bin`, `C:\Windows\System32`, `SysWOW64`)
and the writer process `System`, and offer only the dropped or executed
artifact.

**Custom detection rules (IOA)** carry `rule_instance_name`, `rule_group_name`
and `prevention_policy_name`. Show the rule name in the verdict: a custom rule
firing on admin tooling is usually an expected-behaviour review, not malware.

**Write-back** (status and comment on the CrowdStrike alert, network
containment) needs the **Alerts: Write** and **Hosts: Write** scopes. Without
them the step fails; report "update failed — check the API client's scopes"
rather than stopping the run (`ignore_errors: true`).

---

## FortiSIEM — incident write-back

`update_incident`, `clear_incident` and `incident_comment` (connector v6.2.0),
including the trap that a failed update **does not raise**, are documented in
`fortisiem-queries.md`, "Writing back to FortiSIEM".

## Microsoft WinRM — updating a firewall EDL file

See `winrm-edl.md`.

## Email ingestion (IMAP, Exchange)

What an email alert's `sourcedata` holds, and the Exchange connector's setup
traps, are in `email-ingestion.md`.
