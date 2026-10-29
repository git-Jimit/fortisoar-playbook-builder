# Email ingestion — what an email alert holds, and the Exchange connector

Read this before building any phishing or email-analysis playbook, and before
deciding the trigger.

Sources: the sample ingestion playbooks shipped in the **IMAP 3.5.8** and
**Exchange 4.8.0** connector packages (read from the packages), and real
reported-phishing alerts from a production instance ingested over IMAP
(October 2026). Exchange alerts were not yet seen on a live instance — their
shape below comes from the connector's own code, which uses the same parser.

## The alert's `sourcedata`

Both connectors parse mail with FortiSOAR's email parser (`explode_email` —
IMAP calls the `cyops_utilities` one, Exchange bundles its own copy) and
create the alert with `sourcedata = {{ <email> | toJSON }}` — so **`sourcedata`
is usually a JSON string** (pitfall 34). Parsed, it looks like:

```
{ "headers":  { "from": "...", "to": "...", "subject": "...", "received": [ ... ],
                "authentication-results": "...", ... },
  "body":     { "text": "...", "html": "..." },
  "attachments":      [ { "file": "...", "metadata": { "filename": "...", "content_type": "...",
                                                       "content_length": 1639600, "md5": "...",
                                                       "sha1": "...", "sha256": "..." } } ],
  "attachment_files": [ ... ],
  "parsed_attachment_data": [ <an attached .eml/.msg, parsed the same way> ],
  "preamble": "", "epilogue": "",
  "reporterEmailAddress": "...",          // only for a reported email
  "reporterEmailBody":   { "text": "...", "html": "..." } }
```

- **A header that appears more than once is a list** (`received`, often
  `arc-seal`). Read headers case-insensitively and accept a string or a list.
- **Exchange lower-cases header names** (`get_email_new` passes
  `updated_headers=True`); IMAP keeps the original case. A case-insensitive read
  handles both.
- **Reported email** (a user forwards the suspicious mail **as an attachment**):
  the ingestion's "Process Email" playbook replaces the alert data with the
  **attached** email (`parsed_attachment_data[0]` on Exchange, each attachment on
  IMAP) and adds `reporterEmailAddress` and `reporterEmailBody`. So
  `headers` and `body` are the **suspicious** email, and the reporter is in
  `reporterEmailAddress`. Exchange makes one alert from the first attached
  message only; IMAP one per attached message.
- **Inline forward** (the user clicks Forward): no attachment — the original
  sender sits inside the body text ("From: … Sent: … Subject: …"). Detect it, or
  the forwarding colleague is analysed as the sender.
- Bodies can be **megabytes** because of inline base64 images, and the reporter's
  original mail may also be embedded. Never render `sourcedata` whole into a
  code snippet — build a trimmed dict and strip base64 (pitfall 33), inject free
  text with `unquote_plus` (pitfall 43), and scrub emoji (pitfall 44).

## Alert fields the sample ingestion sets

Both connectors' sample playbooks set: `name` (the subject), `source`,
`sourceId` (Message-ID), `emailFrom`, `emailTo`, `emailSubject`, `emailHeaders`
(as JSON), `emailBody`, `senderDomain`, `senderEmailAddress`,
`recipientEmailAddress`, `returnPath`, `reporter`, `reporterEmailBody`,
`fileHash` and `fileNames` (comma lists), `sourcedata`. The Exchange sample also
creates file indicators and attachment records and links them to the alert, and
can create a Communications record.

**`source` is `"User Reported"`** when `reporterEmailAddress` is present, **else
`"Email Server"`** — in both packages. It is **not** the connector's name. A
trigger on `source = IMAP` only works if the ingestion was customised; check a
real alert before writing the trigger, and use both values for a playbook that
should see every email alert.

## Exchange connector (v4.8.0) — setup traps

Read from the connector package and Microsoft's announcement; not every point
was exercised live.

**Only outbound TCP 443** is needed: FortiSOAR → the Exchange host
(on-premises) or `login.microsoftonline.com` + `outlook.office365.com`
(Office 365). The "Email Notification Service" uses a streaming subscription over
the same 443; its *Listener Port* (default 10011) is local to the FortiSOAR
server and needs no firewall rule. Nothing connects inbound.

**On-premises:** Host = the server name only (no `https://`, no `/EWS/...`);
username as UPN, or `DOMAIN\user` if the UPN is rejected; Email Address = the
mailbox to read; Access Type DELEGATE; Autodiscover off. Reachability check from
FortiSOAR: `curl -vk https://<host>/EWS/Exchange.asmx` should answer **401**.

**Shared mailbox:** connect as a service account and put the **shared mailbox
address** in *Email Address* (DELEGATE). The admin grants the account
`Add-MailboxPermission -Identity <shared> -User <svc> -AccessRights FullAccess
-InheritanceType All -AutoMapping $false`, plus *Send As* only if FortiSOAR
must send from it. Prefer this over IMPERSONATION, which reaches every mailbox.

**Office 365 — the connector uses EWS, which Microsoft is retiring in Exchange
Online:** blocked from **1 October 2026** unless the tenant has
`EWSEnabled=True` and an app allow-list, and removed with no way back on
**1 April 2027**. On-premises Exchange is not affected. Tell the client, and plan
Microsoft Graph-based ingestion for Office 365 tenants.

**Office 365 authentication:** prefer **"Without a User – Application
Permission"** (Tenant ID, Client ID, client secret; Exchange application
permission `full_access_as_app`, or the scoped RBAC role
`Application EWS.AccessAsApp` with a management scope limited to the phishing
mailbox). It runs unattended.

**"On behalf of User – Delegated Permission" has a connector bug.** After the
sign-in, the connector stores the token it received; when that token comes back
empty it crashes with `'NoneType' object has no attribute 'get'` (in
`update_config`) and hides the real cause. Typical causes: the authorization code
was already used or expired (single use, ~10 minutes), the pasted value included
`&session_state=…`, or the redirect URI or scope did not match the app
registration. If delegated access is required: delegated permission
`EWS.AccessAsUser.All`, a Web redirect URI, sign in as the mailbox user, paste
**only** the `code` value and save within minutes. The real error is in
`/var/log/cyops/cyops-integrations/connectors.log`.
