# FortiSIEM Query Steps — Pattern Reference

The most common building block. Use this whenever a playbook needs to pull, count or correlate events from FortiSIEM.

## The connector operation

```json
{
  "name": "Fortinet FortiSIEM",
  "config": "<config uuid from the user's instance - see conventions.md>",
  "params": {
    "to": "{{vars.item.to_time}}",
    "cond": "{{vars.item.cond}}",
    "from": "{{vars.item.from_time}}",
    "start": 0,
    "groupby": "{{vars.item.groupby}}",
    "orderby": "COUNT(*) DESC",
    "perPage": 200,
    "AttrList": "{{vars.item.AttrList}}",
    "query_type": "Basic Query",
    "time_selection": "Absolute Time"
  },
  "version": "6.1.1",
  "for_each": { "item": "{{vars.query_plan}}", "parallel": false, "condition": "" },
  "connector": "fortinet-fortisiem",
  "operation": "run_report",
  "operationTitle": "Run Advanced Search Query",
  "pickFromTenant": false,
  "step_variables": { "sweep_results": "{{ vars.steps.Run_TTP_Query }}" }
}
```

---

# The result shape — get this right or every downstream snippet breaks

This is the single most important thing in this file. The response is **not** a flat list of row-dicts.

A `for_each` connector step returns:

```json
{
  "result": [
    {
      "data": {
        "@start": "0",
        "@totalCount": "3",
        "@errorCode": null,
        "events": [
          {
            "id": "0",
            "index": "0",
            "attributes": {
              "COUNT(*)": "580",
              "DNSQNAME": "qx7kpm2d.example-dga.net",
              "DNSInitiatorIP": "100.64.12.34",
              "attribute": [ { "#text": "580", "@name": "COUNT(*)" }, ... ]
            }
          }
        ]
      }
    }
  ]
}
```

Four things to handle:

1. **Unwrap `result`** — the for_each output is `{"result": [...]}`, one entry per plan item, in plan order.
2. **Rows live at `data.events[].attributes`**, not at the top level.
3. **Drop the duplicated `attribute` key** — each row carries both a flat dict and a redundant array form of the same data.
4. **`@totalCount` is the real count.** `len(events)` is the returned page and **saturates at `perPage`**. Scoring on row count silently understates every busy query. Also read `@errorCode` — a non-null value means that query failed while the others succeeded.

Canonical parser:

```python
def slot(res):
    """Return (rows, total_matching, errorCode) for one query result."""
    d = res if isinstance(res, dict) else {}
    if "events" not in d and isinstance(d.get("data"), dict):
        d = d.get("data")
    ev = d.get("events") if isinstance(d, dict) else None
    if isinstance(ev, dict):
        ev = [ev]
    if ev is None or isinstance(ev, (str, int, float, bool)):
        ev = []                       # portable: no isinstance(x, list) needed
    rows = []
    i = 0
    while i < len(ev):
        a = ev[i].get("attributes") if isinstance(ev[i], dict) else None
        i = i + 1
        if isinstance(a, dict):
            r = {}
            for k in a:
                if k != "attribute":
                    r[k] = a[k]
            rows.append(r)
    tc = d.get("@totalCount") if isinstance(d, dict) else None
    try:
        tc = int(str(tc))
    except Exception:
        tc = len(rows)
    return rows, tc, (d.get("@errorCode") if isinstance(d, dict) else None)
```

---

# `cond` — query condition syntax

- Comparisons: `eventType = "Win-Security-4625"`, `user NOT CONTAIN "$"`, `srcIpAddr = "1.2.3.4"`
- Combinators: `AND`, `OR`, parenthesise groups
- `CONTAIN` / `NOT CONTAIN` for substring matches
- Multiple event types are OR'd: `(eventType = "A" OR eventType = "B")`
- Always scope to the tenant: `AND (customer = "<Org Name>")`

## CONTAIN is a substring test, and that bites

There is no anchoring. Real failures caused by forgetting this:

| Intent | Written as | Also matched | Fix |
|---|---|---|---|
| exclude RFC1918 | `destIpAddr NOT CONTAIN "10."` | `210.5.4.3` — real public addresses excluded | compare octets in a Code Snippet |
| high-risk TLD `.work` | `DNSQNAME CONTAIN ".work"` | `workline.hr`, `workers.dev`, `workspaceone.com` | extract the last label in a Code Snippet |
| exclude a screensaver path | `filePath NOT CONTAIN "screensaver"` | `c:\users\bob\downloads\screensaver\evil.scr` | `filePath != "c:\screensaver"` |
| CORS header present | `CONTAIN "Set-Mailbox"` | `Set-MailboxPlan`, `Set-MailboxAutoReplyConfiguration` | list exact event types |

**Rule: anything needing a suffix, prefix or numeric comparison belongs in post-processing, not in `cond`.** Query broadly, filter precisely in Python where the logic can be expressed correctly.

---

# `groupby` / `AttrList` / `orderby`

- `groupby` — attributes to aggregate on, e.g. `"user,srcIpAddr,hostName"`. Empty string for a raw event list.
- `AttrList` — columns returned. When grouping, include `COUNT(*)` last.
- `orderby` — usually `"COUNT(*) DESC"`.

**Every attribute you group by must be one the event type actually parses.** A valid attribute name that the parser does not populate returns blank, and a filter on it matches nothing. See `pitfalls.md` — this has produced detections that were dead for months while looking clean.

---

# Managing query cost — the difference between 2 minutes and a timeout

FortiSIEM Advanced Search is asynchronous; the connector polls and gives up after roughly five minutes with `Query progress status is still in progress` and a 400. Tables of 50–100M rows are normal, so this is a design constraint, not an edge case.

**1. One query per question, not per subject.** The single biggest win. If five hosts each need the same five checks, that is 5 queries, not 25 — put the host in the grouping and split the rows afterwards.

```
BAD   srcIpAddr = "10.1.1.1"                          (x5 hosts x5 checks = 25 queries)
GOOD  (srcIpAddr = "10.1.1.1" OR srcIpAddr = "10.1.1.2" OR ...)     (5 queries)
```

**2. Deduplicate identical queries.** Two checks that send the same `cond`/`groupby`/`AttrList`/window and differ only in post-processing should run once and share the result. Build the plan, hash each query's signature, and have both checks point at the same result index.

**3. Cap the window per query.** A check against a 47M-row table does not need 24 hours. Let each plan entry carry its own `max_hours` and clamp it.

**4. Pre-filter before aggregating.** `SUM()` grouped over 120M unfiltered rows times out. Add a floor — `AND (sentBytes64 > 1048576)` — and state the trade-off in a comment.

**5. Shard long chains across steps.** Split the plan across two or three connector steps so one slow query cannot take the whole run, and *Rerun From Last Failed Step* resumes rather than restarting. Reassemble by a recorded global slot index, never by concatenation order.

**6. Spread expensive queries.** When sharding, deal the heavy aggregations out one per step rather than round-robin, so two never land together.

---

# The query-plan pattern

For several related queries, do not hardcode N connector steps.

1. A **Code Snippet** builds a list of query dicts — each with `cond`, `groupby`, `AttrList`, `from_time`, `to_time`, `perPage`, plus whatever metadata post-processing needs.
2. One **Connector Operation** with `for_each.item: "{{vars.query_plan}}"` runs it once per entry, `params` referencing `{{vars.item.cond}}` etc.
3. A follow-up **Code Snippet** interprets the results.

**Verify alignment before scoring.** Results come back positionally. If a query fails and its slot is missing, everything after it is attributed to the wrong check — silently, and the report looks normal. Either compare `len(results)` to `len(plan)` and refuse to score on mismatch, or carry an explicit slot index and reassemble by it.

---

# Querying incidents and ordering events

**An incident is queryable with `run_report`** — useful when a production rule
allows only queries, not the other FortiSIEM actions (verified on production):

```
phEventCategory = 1 AND incidentId = 19596090 AND customer = "<Org>"
AttrList: phRecvTime,incidentStatus,hostName,incidentDetail
```

Each row is one firing of the rule, so `@totalCount` is how often it fired.
`incidentStatus` comes back as `"0 (Active)"` / `"2 (Manually Cleared)"`, and
`incidentDetail` is wrapped as `lt;![CDATA[{...}]]gt;` — strip the wrapper before
parsing. The incident's vpnTunnelName-style detail fields live only in
`incidentDetail`, not in the matching event attribute.

**Same-second events are not ordered.** `phRecvTime` and `deviceTime` have
1-second resolution, and several events of one change (e.g. a tunnel's
`phase2-down`, `tunnel-down`, `phase2-up`) arrive in the same second in any
order. Order them by a sub-second field in the raw log — FortiGate's `eventtime`
is nanoseconds since the epoch. The same limit explains a rule pattern that
misfires: `A NOT_FOLLOWED_BY B` treats a `B` logged in the same second as not
following `A`.

**A log collector can double every event.** When a device also forwards through
FortiAnalyzer (or another relay), FortiSIEM stores both copies under different
`reptDevIpAddr`/`reptDevName` values, and every rule grouped by reporting device
raises two incidents per event. Check with a grouped count by
`reptDevIpAddr,eventType`; dedupe on the raw `eventtime` + a session/cookie field.
On relayed copies `devname` may be the serial number and `deviceTime` can be
shifted by the timezone — order by the raw `eventtime`, not `deviceTime`.

# Other operations

- `get_associated_events` — events tied to a FortiSIEM incident id
- `get_incident_details` — full incident context by id
- `get_all_lookup_tables` — enumerate lookup tables

Same step shape; change `operation`, `operationTitle` and `params`.

---

# FortiSIEM-ingested alert sourcedata

What a FortiSOAR alert created by FortiSIEM ingestion actually holds. Observed on
real client alerts (October 2026); field names are as they appeared there.

```
{ "incident_data": { "incidentId": 12345, "incidentDetail": "{\"webCategory\":\"malware\"}",
                     "incidentSrc": {"srcIpAddr": "10.1.2.3"}  -or-  "srcIpAddr:10.1.2.3,",
                     "incidentTarget": ..., "incidentFirstSeen": 1760000000000, "incidentLastSeen": ... , ... },
  "associated_events": [ { "id": "...", "nid": "...", "eventType": "...",
                           "attributes": { "Source IP": "...", "Firewall Action": "...", ... },
                           "rawMessage": "...", "receiveTime": "..." } ] }
```

- The event list is **`associated_events`**, not `events`. An alert can exist
  with only `incident_data` before its events are attached — read both shapes.
- `attributes` keys are **display names with spaces**: `"Informational URL"`,
  `"Destination Host Name"`, `"Web Site Category"`, `"Firewall Action"`,
  `"Source Host Name"`, `"Destination TCP/UDP Port"`, `"Application Name"`,
  `"Device Time"` (epoch **ms**), `"Firewall Rule"`, `"Reporting Device"`.
  Read them as `at['Firewall Action']`, never `at.firewallAction`.
- `incident_data.incidentDetail` is a **JSON string** — parse it (`| toDict` in
  jinja, `json.loads` in code).
- `incidentSrc` / `incidentTarget` can be an **object** (`{"srcIpAddr": ...}`)
  **or** a `"srcIpAddr:x,destIpAddr:y,"` **string**. Handle both.
- `incidentFirstSeen` / `incidentLastSeen` / `Device Time` are epoch
  **milliseconds** — divide by 1000 before formatting.
- The whole `sourcedata` may itself be a JSON string (pitfall 34).

A read that is safe on every shape (pitfall 39 explains the `is defined` test):

```
{% set sd = vars.input.records[0].sourcedata %}
{% set sd = sd if sd is mapping else (sd | default('{}', true)) | toDict %}
{% set inc = sd.incident_data if (sd.incident_data is defined and sd.incident_data is mapping) else {} %}
{% set v = sd.associated_events %}
{% set evs = v if (v is defined and v is iterable and v is not string and v is not mapping) else [] %}
{{ {'incident': inc, 'events': evs[:50]} | tojson }}
```

Incident id for write-back steps:
`{{ (vars.input.records[0].sourcedata if vars.input.records[0].sourcedata is mapping else (vars.input.records[0].sourcedata | toDict)).incident_data.incidentId }}`

---

# Writing back to FortiSIEM (connector v6.2.0)

From the connector source (`info.json`, `operations.py`, `constants.py`). All
three POST to `/rest/incident/external`.

| Operation | Title | Params | Effect |
|---|---|---|---|
| `update_incident` | Update Incident | `incidentId` (required), `comments`, `incidentStatus` (Active / Manually Cleared / System Cleared / Auto Cleared), `severity` (HIGH / MEDIUM / LOW), `resolution` (True Positive / False Positive), `externalTicketType` / `Id` / `State`, `externalAssignedUser` | Status, resolution and comment in one call |
| `clear_incident` | Clear Incident With Reason | `id`, `comment_text` | Status 2 (Manually Cleared) plus a comment — **no resolution** |
| `incident_comment` | Comment Incident | `id`, `comment_text` | Comment only |

- Status codes: Active 0, Auto Cleared 1, Manually Cleared 2, System Cleared 3.
  Resolution: True Positive 2, False Positive 3.
- **Prefer `update_incident` for closing** — only it records True / False
  Positive.
- **A failure does not raise.** The step succeeds with
  `data.message: "Provided incident does not exist"`; success reads
  `"Incident updated"` / `"Successfully cleared…"` (only when the API returns
  `"OK"`). Check `data.message`, and tag the alert when the write-back failed.
- Before adding any write-back, check what else writes back on alert updates
  (pitfall 41), and never write back an outcome after a placeholder action
  (pitfall 42).
