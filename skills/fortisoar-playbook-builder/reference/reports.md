# Reports: PDF on the record, HTML for mail

Read this when a playbook must produce something a person reads outside the
FortiSOAR UI: a PDF attached to the alert, an emailed report, or both.

## The pattern

One Code Snippet builds **both** outputs from the same data, then two plain
steps deliver them:

```
… → Build Report (code)  →  Attach Report to Alert (Update Record)  →  Email Report (optional connector)
```

The code snippet's output contract — keep these names, other steps and
connectors read them:

```json
{"status": "Success", "message": "", "report_id": "RPT-…", "filename": "RPT-….pdf",
 "attachment_iri": "/api/3/attachments/…", "attachment_iris": ["/api/3/attachments/…"],
 "html": "<!DOCTYPE html>…"}
```

- `attachment_iris` is a list so the Update Record step can append it directly.
- `html` is a complete document for an HTML-to-PDF / email connector. The
  RichTexttoPDFandEmail connector's `dataForPDF` takes the whole `code_output`
  dict and reads `html` from it (see `connector-responses.md`).
- Wrap the PDF build in `try` and report failure in `status` / `message`. A
  report that fails must not take the response actions down with it; give the
  step `ignore_errors: true` as well.

## Building the PDF: `assets/pdf_report_engine.py`

The sandbox has no PDF library and blocks direct file access, so the engine
draws the PDF from primitive operators and stages the file through `zipfile`.
It came out of a production phishing-report playbook and was reused unchanged
for a FortiDeceptor incident report on the same instance.

Paste the file into the snippet after your data preparation, set the
`REPORT_*` values, then:

```python
new_page()
banner("SEVERITY: CRITICAL", scenario, attacker_ip, "External source", "critical")
sec("Incident summary")
key_value([["Alert ID", alert_id], ["Target", target]])
sec("Timeline")
data_table(["Time", "Event", "Severity"], rows, [30, 45, 25], {2: True})
body_text(recommendation)
pdf = finish_pdf()
entry = attach(safe_name(REPORT_ID_TXT, "Report", ".pdf"), pdf, "note")
```

`data_table`'s last argument maps a column to `True` to draw that cell as a
badge coloured by its own text (`critical`, `high risk`, `malicious`, …).

What it already handles, so do not re-solve it:

- **Characters outside Latin-1.** `₹` prints as `Rs.`, curly quotes and dashes
  are straightened, emoji and zero-width characters are dropped. Otherwise they
  print as `?`. Emoji arrive as UTF-16 surrogate pairs after a JSON round trip,
  which is why they need dropping explicitly.
- **Long unbroken tokens** — URLs, header values — are cut to the column width
  instead of running off the page.
- **Page breaks.** `sec()` keeps a heading with the block after it.
- **Time zones.** Appliance clocks are often UTC while reports are read in local
  time; `REPORT_DATE_TXT` and `epoch_ist()` apply `REPORT_UTC_OFFSET_MINUTES`
  and label it `REPORT_TZ_LABEL` (default UTC). Set both for your region.

## When the client already has a report template

If the client has a playbook that already draws their branded PDF in a code
snippet (cover, banner, footer, logo), reuse **their** engine rather than
`pdf_report_engine.py`: lift its drawing primitives, PDF writer, template
artwork and file staging unchanged, and write only your page layout on top. The
report then matches what their customers already receive. Two things to check:
it must avoid the banned builtins (`conventions.md`), and it may only know
Helvetica — adding a fixed-width font for raw logs is three small edits (a font
object, the resource dictionary, and a `mono` flag on text ops).

A client-facing report should also carry what a non-specialist needs: a
one-paragraph plain-language explanation of what the alert means, the events and
raw logs behind it, the enrichment as its own section, and actions they can take
— and no internal notes (failed queries, connector errors).

## Re-running without duplicating a summary

When a playbook writes a summary into the record's description, wrap it in
marker paragraphs (`[... summary - start]` / `[... summary - end]`) and remove the
old block before prepending the new one, so a re-run replaces it and the
original description stays intact.

## Linking it to the record

`attach()` uploads the file and creates an Attachment record. That record is
**not** on the alert until you link it — pitfall 38. The step:

```json
{"when": "{{ vars.steps.Build_Report.data['code_output']['attachment_iri'] | string | length > 0 }}",
 "resource": {"attachments": "{{ vars.steps.Build_Report.data['code_output']['attachment_iris'] }}"},
 "operation": "Append", "fieldOperation": {"attachments": "Append"},
 "collection": "{{ vars.input.records[0]['@id'] }}", "collectionType": "/api/3/alerts",
 "ignore_errors": true}
```

## Emailing the PDF

Send the file itself with the SMTP `send_email` operation and the attachment IRI
in `iri_list` — verified on a production instance; the full step is in
`step-types.md` §15. With an empty `iri_list` the email still sends, just without
the report, so guard the step on the IRI being non-empty.

## Emoji and surrogates outside the PDF

The engine drops emoji when drawing. That does not protect the **code step**: if
emoji reach the step's input or its printed output, the step can fail with a bare
500 before any PDF exists (pitfall 44). Scrub the decoded data at the top of the
snippet as well.

## Writing the HTML

Converters and mail clients render far less CSS than a browser:

- A full document: `<!DOCTYPE html>`, `<meta charset="UTF-8">`, one `<style>` block.
- Layout with **tables**, not flexbox or grid.
- Escape every value that came from data (`html_escape()` in the engine). An
  address like `Name <user@example.com>` otherwise disappears as an unknown tag.

## What never goes into a report

- **Credentials** the attacker tried. Deception and brute-force events carry the
  attempted password in clear; redact it and say that you did.
- API keys, session tokens, or any secret from a connector response.
- The whole `sourcedata` — summarise it. It can also be large enough to break
  the snippet itself (pitfall 33).
