# Reports: PDF, HTML, Excel, CSV and other files

Read this when a playbook must produce something a person reads outside the
FortiSOAR UI: a PDF attached to the alert, an emailed HTML report, an Excel
workbook or CSV export, or any combination of them.

| Format | Use it for | How |
|---|---|---|
| PDF | A formal report a client keeps | "Building the PDF" below |
| HTML | The mail body; also the input of an HTML-to-PDF connector | "Writing the HTML" below |
| Excel (`.xlsx`) | Lists a person filters and sorts: IOC feeds, blocked lists, asset or finding tables, several sheets in one file | "Building an Excel workbook" below |
| CSV | A flat list another tool imports, or a quick export | "Building a CSV file" below |
| JSON / TXT | Machine-readable output or a plain feed | "Other file types" below |

All of them are built in one Code Snippet from the same data, and delivered the
same way: attached to the record, mailed, or both ("Delivering a file").

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

## Building the PDF

The sandbox has no PDF library and blocks direct file access. A working PDF
engine therefore draws the document from raw PDF operators and stages the file
through `zipfile`. One was built for a production phishing-report playbook and
reused unchanged for a FortiDeceptor incident report on the same instance. In
order of preference:

1. **The client's own report engine**, if a playbook on their instance already
   draws their branded PDF (see the next section).
2. **`pdf_report_engine.py` from the tools repository**
   (github.com/git-Jimit/fortisoar-playbook-tools). Fetch it if you can reach
   the web, or ask the user to paste it. Paste it into the snippet after your
   data preparation.
3. **The same method, written fresh**, when neither is available. Follow "How
   the engine works" below exactly. Every point in it is there because the
   obvious alternative failed in the sandbox.

### How the engine works

- **Imports.** Only `json`, `re`, `struct`, `zipfile` and `datetime` /
  `timedelta`, plus the sandbox-safe builtins (`conventions.md`). Write no
  `set`, `any`, `all`, `enumerate`, `sum`, `max`, `min`, `map`, `filter` and no
  `lambda`. No reportlab or fpdf: they are not installed.
- **Fonts.** The two standard Type 1 fonts, `Helvetica` and `Helvetica-Bold`,
  with `/Encoding /WinAnsiEncoding`. They need no embedding. Text must be
  Latin-1, so map characters outside it before drawing:
  - `₹` → `Rs.`, `€` → `EUR`, `…` → `...`;
  - curly quotes → straight quotes, en and em dashes → `-`, bullets → `-`;
  - emoji, zero-width characters and lone surrogates → drop them;
  - anything else → `?`.
- **Measuring text.** Wrapping, centring and right-aligning need character
  widths. The engine carries the Helvetica and Helvetica-Bold advance widths
  for codes 32–126 (units per 1000; the regular space is 278, `M` is 833).
  Without the table, estimate 556 per character at regular weight and 611 at
  bold, and leave a margin; a too-wide line runs into the next column.
- **Page model.** A4 is 595.276 × 841.890 points, with a 40-point margin.
  - Keep a cursor `y` measured from the top; PDF coordinates start at the
    bottom, so draw at `PG_H - y`.
  - Before each block, check whether it fits above the footer (y ≈ 792) and
    start a new page if not.
  - Keep a section heading on the same page as the block after it, by
    requiring about 80 points of room first.
- **Drawing primitives.** Each page is a list of three kinds of operations,
  later turned into a content stream:
  - rectangle: `x y w h re f` (fill) or `re S` (stroke), colour set with `r g b rg` / `RG`;
  - line: `m … l S`;
  - text: `BT /F1 size Tf r g b rg x y Td (escaped) Tj ET`.
  Escape `\`, `(` and `)` inside text strings.
- **Layout helpers** to write on top:
  - `new_page()`, which draws a navy header band with title, report id and date;
  - `sec(title)`, a grey heading bar;
  - `key_value(rows)`, a two-column detail table;
  - `data_table(header, rows, widths_percent, badge_cols)`, which wraps each
    cell to three lines, stripes rows, and repeats the header after a page break;
  - `banner(headline, subline, right_top, right_bottom, kind)`, the coloured
    verdict box;
  - `body_text(text)`;
  - `finish_pdf()`, which stamps a "Page N" footer on every page and returns
    the bytes.
- **Long tokens.** A URL or header value wider than its column is cut into
  pieces that fit, never left to run off the page. Text that does not fit in its
  line cap ends in `...` rather than being dropped silently.
- **Writing the file.** Assemble a PDF 1.4 file:
  - objects in order: font, bold font, page tree, a content stream and page
    object per page, then the catalog;
  - an `xref` table of byte offsets (10 digits, `00000 n`);
  - a `trailer` with `/Size` and `/Root`, then `startxref` and `%%EOF`.
  Compute offsets from the encoded bytes, not from string lengths.
- **Saving it.** There is no `open()` and no `os`, so write the bytes as a
  member of a zip at `/tmp/<something>.pkg` with
  `zipfile.ZipFile(..., "w").writestr(name, blob)`. Then reopen it and
  `extract(name, "/tmp")`, which leaves a plain file at `/tmp/<name>`.
- **Attaching it.** Upload with:

  ```python
  from connectors.cyops_utilities.builtins import upload_file_to_cyops
  att = upload_file_to_cyops(file_path=path, filename=name, create_attachment=True,
                             name=name, description=note)
  ```

  Read the attachment IRI from `att["@id"]`, falling back to `att["iri"]`, and
  the file IRI from `att["file"]["@id"]`. Return them in the output contract
  above. Uploading does not link the file to the alert (next sections).
- **Time zones.** Appliance clocks are often UTC. Add the client's offset in
  minutes (330 for UTC+05:30) to every timestamp you print, and print the zone
  label next to it.

With the tools-repository engine, set the `REPORT_*` values, then:

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
the tools-repository engine: lift its drawing primitives, PDF writer, template
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

## Building an Excel workbook

There is no openpyxl or xlsxwriter in the sandbox, and none is needed. An
`.xlsx` file is a zip archive of a few small XML parts, and `zipfile` is
available. This method is taken from a production playbook that builds a
two-sheet IOC feed export every day and mails it to the client.

**Writing it.** `zipfile.ZipFile("/tmp/<name>.xlsx", "w", zipfile.ZIP_DEFLATED)`
creates the file directly. Because the workbook *is* the zip, it needs no
staging trick, unlike the PDF. Write these parts with `writestr`, and no others:

| Part | Content |
|---|---|
| `[Content_Types].xml` | Defaults for `rels` and `xml`, plus an `Override` for `/xl/workbook.xml`, `/xl/styles.xml`, `/docProps/core.xml` and each `/xl/worksheets/sheetN.xml` |
| `_rels/.rels` | Relationships to `xl/workbook.xml` (officeDocument) and `docProps/core.xml` (core-properties) |
| `docProps/core.xml` | `dc:title` and `dc:creator` |
| `xl/workbook.xml` | `<sheets>` with one `<sheet name=… sheetId=N r:id="rIdN"/>` per sheet, and optional `<definedNames>` |
| `xl/_rels/workbook.xml.rels` | `rIdN` → `worksheets/sheetN.xml` for each sheet, then one more id → `styles.xml` |
| `xl/styles.xml` | Fonts, fills, borders and the `cellXfs` list; a cell's `s="N"` is an index into `cellXfs` |
| `xl/worksheets/sheetN.xml` | `<sheetData>` with `<row r="…">` and `<c r="A1" …>` cells |

**Cells.**
- Write text as **inline strings**:
  `<c r="B5" s="4" t="inlineStr"><is><t xml:space="preserve">…</t></is></c>`.
  This avoids a shared-strings part entirely.
- Write numbers as `<c r="A5" s="6"><v>12</v></c>`, so Excel can sort and sum them.
- Build cell references from a column-letter list (`"ABCDEFGHIJKLMNOPQRSTUVWXYZ"`)
  and a running row counter. No `enumerate`.

**Escaping.** Before writing any value:
- remove the control characters `\x00`–`\x08`, `\x0b`, `\x0c` and `\x0e`–`\x1f`,
  which make the file "unreadable" in Excel;
- then escape `&`, `<`, `>` and `"`.

**Layout that makes it readable**, all plain sheet XML:
- **Title rows:** a title, subtitle and stats band in rows 1–3, merged across the
  columns with `<mergeCells>`.
- **Header:** a styled header in row 4, with the panes frozen under it:
  `<pane ySplit="4" topLeftCell="A5" activePane="bottomLeft" state="frozen"/>`.
- **Widths:** column widths with `<cols><col min max width customWidth="1"/></cols>`.
- **Rows:** zebra striping, by picking the alternate style id on even rows.
- **Filter:** an `<autoFilter ref="A4:E<last>"/>` on the data, plus the matching
  hidden `_xlnm._FilterDatabase` defined name in the workbook.
- **Status colours:** coloured status cells, for example green for Valid and red
  fill for Invalid, each its own `cellXfs` entry.
- **Printing:** print titles (`_xlnm.Print_Titles` = `$4:$4`), fit to width,
  and a footer with `&amp;P of &amp;N`.

**Limits and edge cases.**
- **Sheet names:** at most 31 characters, and none of `[ ] : * ? / \`.
- **Cell size:** a cell holds at most 32,767 characters; a sheet at most
  1,048,576 rows.
- **Empty data:** never write an empty sheet with only a header. Write one row
  saying why it is empty: "No entries in UBI_IP.txt", or "Could not read
  UBI_IP.txt". The reader can then tell "nothing found" from "the fetch failed".
- **Duplicates and bad values:** drop duplicates and count them, and mark values
  that fail validation (an IP that does not parse, a domain that does not match
  the domain pattern) rather than dropping them. Report the counts in the stats
  band and in the mail body.
- **Failures:** wrap the write in `try`. On failure, return an empty `file_path`
  and the error text, so the mail step can say "no attachment was produced"
  instead of failing.

**Output contract** for the step:
```json
{"file_path": "/tmp/X_20261112_0900.xlsx", "file_name": "X_20261112_0900.xlsx",
 "error": "", "subject": "...", "email_body_html": "<div>…</div>", "<count fields>": 0}
```

## Building a CSV file

For a flat list another tool will import.

- **Write the text yourself.** Do not rely on the `csv` module: it needs a file
  object, and `open()` is not available.
  - Join the fields with `,`.
  - Wrap a field in double quotes when it contains a comma, a quote, a CR or an LF.
  - Double any quote inside a quoted field.
  - End rows with `\r\n`.
- **Start the file with a UTF-8 byte-order mark** (`"﻿"`) when people will
  open it in Excel. Without it, Excel reads non-ASCII text as garbage. Leave the
  BOM out when another program imports the file.
- **Guard against formula injection.** A field that starts with `=`, `+`, `-`
  or `@` runs as a formula when opened in Excel, and attacker-controlled data
  (URLs, subjects, user agents) can start that way. Prefix such fields with `'`.
- **Save it with the zipfile staging trick** from "How the engine works": write
  the encoded bytes as a zip member, then `extract` it to `/tmp`. There is no
  `open()`.
- **Return the same contract** as the Excel step (`file_path`, `file_name`,
  `error`).

## Other file types

- **JSON / TXT:** encode the text, then stage it to `/tmp` exactly like the CSV.
- **Any other format** a person or tool needs can be built the same way if it
  is text, or if it is a zip of text parts as `.docx` and `.pptx` are. The
  limits are the sandbox's, not the format's: no third-party libraries, no
  `open()`, and the banned builtins (`conventions.md`).

## Delivering a file

Every file type can be mailed from either of two places, and attached to the
record as well.

**Mail it from `/tmp`.**
- A mail connector that takes a file path sends the file directly. The
  production Excel playbook does this with the Zoho Mail connector:
  `filePath: "{{ vars.report.file_path }}"`, with the HTML summary as `content`.
- The file must be built earlier in the same playbook run, because `/tmp` is not
  kept between runs.

**Mail it from a FortiSOAR attachment.**
- Upload the file first with `upload_file_to_cyops(..., create_attachment=True)`,
  as in the PDF section, and pass the attachment IRI to the mail step instead of
  a path:
  - **SMTP** `send_email`: the IRI goes in `iri_list` (verified; see "Emailing
    the PDF" above, which works for any file type);
  - **Zoho Mail**: the step also has an `fsrAttachments` parameter for
    FortiSOAR attachments. Check its exact format in the connector's
    documentation before relying on it.
- Use this when the file must outlive the run, or when the attachment is already
  on the record, for example a file a user uploaded or one an earlier playbook
  made. The mail step then needs no `/tmp` file at all.

**Attach it to the record.** After the upload, link the attachment IRI with the
Update Record step under "Linking it to the record" above. Uploading alone does
not put it on the alert (pitfall 38).

You can do several of these from the same file: mail it from `/tmp` *and* attach
it, or attach it and mail that attachment.

Always send an HTML summary in the mail body as well: counts, status per source,
and a warning line when a fetch failed. Then the recipient knows what the file
holds before opening it.

## What never goes into a report

- **Credentials** the attacker tried. Deception and brute-force events carry the
  attempted password in clear; redact it and say that you did.
- API keys, session tokens, or any secret from a connector response.
- The whole `sourcedata` — summarise it. It can also be large enough to break
  the snippet itself (pitfall 33).
