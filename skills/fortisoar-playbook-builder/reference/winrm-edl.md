# Microsoft WinRM — updating a firewall EDL file on Windows

Use case: the client's firewall (e.g. a Palo Alto External Dynamic List) reads a
plain text file served from a Windows server, and FortiSOAR adds or removes
indicators in that file.

**Verified** in a live lab (Windows 11 + FortiSOAR, connector v2.1.0): the health
check, Run Command, add (2 IPs added), duplicate check, remove, and the firewall's
HTTP fetch of the EDL all passed.

WinRM is a **response connector**: its configuration selects the client's
server, so never rely on a default configuration (`connector-configs.md`).

## Configuration fields

`protocol` (http / https), `url` (host), `port` (5985 for http, 5986 for https),
`transport_type` (`ntlm` recommended; also basic / credssp), `username`,
`password`, `domain` (NTLM only), `verify_ssl`.

⚠ The connector's defaults are inconsistent — protocol **https** with port
**5985**. Always set protocol and port as a pair.

## Operations

`execute_command` (Run Command), `execute_ps_command` (Run Powershell Command),
**`execute_ps_script` (Run Inline Powershell Script — use this one: the script is
base64-encoded in transit, so there are no quoting problems)**, `execute_script`,
`get_file`, `upload_file`.

**Output:** `data.op_status` (exit code) and `data.op_result`. If the script
prints JSON, the connector **parses it automatically** — read
`vars.steps.<Step>.data.op_result.added`. A non-zero exit raises a ConnectorError.

## Add script (verified)

Duplicate check, write to a temp file then swap, ASCII output:

```powershell
$path = 'C:\EDL\soar_block_ip.txt'
$new  = @({% for i in vars.block_ips %}'{{ i }}'{% if not loop.last %},{% endif %}{% endfor %})
$cur  = @()
if (Test-Path $path) { $cur = @(Get-Content $path | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) }
$added = @($new | Where-Object { $cur -notcontains $_ })
if ($added.Count -gt 0) {
    Set-Content -Path "$path.tmp" -Value ($cur + $added) -Encoding ASCII
    Move-Item -Path "$path.tmp" -Destination $path -Force
}
@{ added = $added; total = $cur.Count + $added.Count } | ConvertTo-Json -Compress
```

## Remove script (verified)

```powershell
$path   = 'C:\EDL\soar_block_ip.txt'
$remove = @({% for i in vars.unblock_ips %}'{{ i }}'{% if not loop.last %},{% endif %}{% endfor %})
$cur    = @()
if (Test-Path $path) { $cur = @(Get-Content $path | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) }
$removed = @($cur | Where-Object { $remove -contains $_ })
$keep    = @($cur | Where-Object { $remove -notcontains $_ })
if ($removed.Count -gt 0) {
    Set-Content -Path "$path.tmp" -Value $keep -Encoding ASCII
    Move-Item -Path "$path.tmp" -Destination $path -Force
}
@{ removed = $removed; total = $keep.Count } | ConvertTo-Json -Compress
```

Why the scripts are written this way:

- **ASCII:** PowerShell 5.1 `-Encoding UTF8` writes a byte-order mark, which
  corrupts the first EDL entry.
- **Temp file + `Move-Item`:** the firewall never fetches a half-written file.
- **Duplicate check:** reruns do not grow the list.
- **Validated input only:** pass indicators that have already been validated as
  an IP, domain or URL — never raw alert text — into the script.
- If the script runs after an analyst decision, record the result (added /
  removed counts) on the alert; never record "blocked" when the step failed
  (pitfall 42).

## Windows prerequisites (each one was hit in the lab)

1. `Enable-PSRemoting -Force -SkipNetworkProfileCheck`, then allow 5985 (or 5986)
   **only from the FortiSOAR IP**.
2. A dedicated **non-admin** user in **Remote Management Users**, with Modify
   rights only on the EDL folder: `icacls <dir> /grant "<user>:(OI)(CI)M"`.
3. **Windows 10/11 only:** the WinRM RootSDDL does **not** include Remote
   Management Users by default (`O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)S:P…`). The
   symptom is `w:AccessDenied, HTTP 500` even with correct credentials. Fix: add
   `(A;;GXGR;;;RM)` before `S:`, then `Restart-Service WinRM`. Windows Server
   includes RM by default.
4. **"Public" network profile:** `Set-Item WSMan:\…` fails with *"WinRM firewall
   exception will not work since one of the network connection types is
   Public"*. Set the profile to Private, or skip setting values that are already
   correct.
5. Reachability from the FortiSOAR CLI:
   `curl -s -o /dev/null -w "%{http_code}\n" http://<host>:5985/wsman` should
   return **405**.
6. Error meanings: **401** = wrong credentials; **500 `w:AccessDenied`** =
   authenticated but not authorised (see 3); **timeout** = network or firewall.
