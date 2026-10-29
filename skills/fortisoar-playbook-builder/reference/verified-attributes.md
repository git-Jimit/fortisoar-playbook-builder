# Verified Attributes — what these event types actually populate

`fortisiem_event_attributes_1.csv` / `_2.csv` prove an attribute **name is valid**. It does not prove the parser **fills it in** for a given event type. Those are different, and confusing them is the most common cause of a detection that returns nothing and looks clean.

Everything below was confirmed against raw events from a live instance. Treat it as ground truth for these event types, and as a warning for every other: **assume nothing, verify before you filter on it.**

---

## Process execution

### `Win-Sysmon-1-Create-Process` — the best process source where present

| Attribute | Carries |
|---|---|
| `procName` | **full image path** — `C:\Windows\SysWOW64\cmd.exe` |
| `shortProcName` | `cmd.exe` |
| `parentProcName` | full parent path |
| `parentCommand` | full parent command line |
| `command` | full command line |
| `hashSHA256` | **populated** |
| `user`, `hostName`, `dirName`, `integrityLevel` | populated |
| `reptDevIpAddr` | **the machine's own IP** — this is the join key |

### `FINS-Windows-new-process-created` (FortiInsight)

| Attribute | Carries |
|---|---|
| `procName` | **short name only** — `wmiprvse.exe`, *not* a path |
| `filePath` | the directory — `c:\windows\system32\wbem` |
| `fileName`, `fileExt` | populated — `wmiprvse.exe`, `exe` |
| `swParam` | full command line with arguments |
| `hashSHA256`, `hashMD5`, `hashSHA1`, `hashSHA512` | **all populated** |
| `reptDevIpAddr` | the machine's own IP |

**The two sources are shaped differently.** Sysmon puts the path in `procName`; FortiInsight puts it in `filePath` and a bare name in `procName`. A path filter written for one returns nothing against the other. Query them as separate steps, or test both fields.

`Win-Security-4688` also carries `command` and `procName`, but is often enabled on only a handful of hosts — check its volume before relying on it.

---

## File activity

`FINS-Windows-file-renamed` / `-created` / `-written` / `-downloaded`:

populated — `fileName`, `filePath`, `fileExt`, `procName`, `shortProcName`, `srcFileName`, `user`, `hostName`, `reptDevIpAddr`, `activityName`

**No hash on the file events** (unlike the process event).

---

## DNS

### `Win-DNS-256-Query-received`

| Attribute | Carries |
|---|---|
| `DNSInitiatorIP` | **the querying client** — this is what you group by |
| `DNSQNAME` | the domain |
| `hostName` / `reptDevIpAddr` | **the DNS server**, not the client |
| `srcIpAddr` | **blank** |

Grouping on `srcIpAddr` returns nothing; grouping on `hostName` attributes every client's lookup to the resolver.

---

## Security controls

### `Trellix-domain-match` / `Trellix-malware-callback`

| Attribute | Carries |
|---|---|
| `srcIpAddr` | the machine that **forwarded** the query |
| `srcName` | that machine's hostname |
| `cncName` | **the actual C2 host** — the indicator worth blocking |
| `signatureName` | the malware family, e.g. `Backdoor.SUNBURST.DNS` |
| `destIpAddr` | **the upstream DNS resolver, not the attacker** |
| `actionTaken` | `notified` means it was logged, not blocked |
| `hostName` | **blank** |

Two traps here: taking the indicator from `destIpAddr` (which would have you blocking your ISP's resolver), and grouping on `hostName` (blank) instead of `srcName`.

### AV events

`Symantec-AV-IPS-Intrusion-Detected` populates `hashSHA256` on some rows. Across ~97 other AV and Deep Security event types, `hashSHA256`, `hashMD5` and `virusName` are **all empty** — including `Symantec-AV-Threat-Protection`. If you need the malware name or the file hash for a detection, it must come from the process events, not from AV.

`TrendMicro-DeepSecurity-*` events set `fileName` to the Windows event log channel (`Security`, `Application`, `System`) — it is not a file.

---

## Windows Security — attributes that look right and are not

| Event | Does **not** populate | Use instead |
|---|---|---|
| `Win-Security-4697` (service installed) | `osObjName` | `serviceName`, `serviceFileName`, `serviceAccount` |
| `Win-Security-4670` (permissions changed) | `osObjName` | `procName`, `osObjType` |
| `Win-Security-5140` (share access) | `osObjName` | `fileName` carries the **share name**, plus `filePath`, `srcIpAddr` |
| `Win-Security-4698` (scheduled task) | `taskName` | `user`, `hostName`, `eventAction` — the task cannot be named from the log |
| `PH_OSQUERY_WIN_POWERSHELL_BAD_PARENT` | `procName`, `parentProcName`, `user` | nothing usable — detail is unparsed |

The `5140` case is worth internalising: a condition matching `osObjName CONTAIN "ADMIN$"` could never match anything, so admin-share lateral movement was undetectable while the detection appeared healthy.

---

## How to verify a new one

Ask the user for a single raw event, not a count:

```
eventType = "<the event type>" AND (customer = "<Org>")
```
Display the attributes you intend to use, plus `COUNT(*)`. One row over 7 days is enough.

FortiSIEM's event detail view lists every parsed field with its **display name** (`DNS Initiator IP`, `Source Host Name`, `Command and Control Host Name`). Map those to attribute names via the CSV — the display name is what appears in the UI, the attribute name is what goes in a query.

If a field you need is absent from the parsed list, it is a coverage gap. Say so and record it, rather than shipping a detection that cannot fire.
