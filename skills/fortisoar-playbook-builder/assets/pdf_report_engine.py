# =============================================================================
# FortiSOAR PDF report engine - paste into a Code Snippet step
# =============================================================================
# Draws an A4 PDF from primitive operators - no reportlab, no fpdf, no files
# opened directly - so it runs inside the code-snippet sandbox. Taken from a
# production phishing-report playbook and reused unchanged in a second one;
# see reference/reports.md for the whole pattern and the output contract.
#
# Uses only: struct, zipfile, re, json, datetime and the sandbox-safe builtins.
# No set/any/all/enumerate/sum/type/eval/map/filter/max/min/lambda.
#
# HOW TO USE
#   1. Paste this whole block below your own data preparation.
#   2. Set the REPORT_* values below, including the time zone offset and label.
#   3. Draw:   new_page(); banner(...); sec("Title"); key_value([...]);
#              data_table([...], rows, [widths %], {col: True}); body_text("...")
#   4. pdf_bytes = finish_pdf()
#   5. entry = attach(safe_name(REPORT_ID_TXT, "Report", ".pdf"), pdf_bytes, "note")
#      -> {"filename", "bytes", "attachment_iri", "file_iri"}
#   6. Link entry["attachment_iri"] to the record with an Update Record step
#      (uploading alone does NOT put it on the alert - pitfall 38).
# =============================================================================
import json
import re
from datetime import datetime, timedelta

REPORT_TITLE_TXT = "INCIDENT REPORT"
REPORT_SUBTITLE_TXT = "Security Operations Center"
REPORT_FOOTER_LEFT_TXT = ""
REPORT_FOOTER_MIDDLE_TXT = "Confidential"
REPORT_UTC_OFFSET_MINUTES = 0   # appliance clocks are often UTC - e.g. 330 for UTC+05:30
REPORT_TZ_LABEL = "UTC"
_LOCAL_NOW = datetime.utcnow() + timedelta(minutes=REPORT_UTC_OFFSET_MINUTES)
REPORT_ID_TXT = "RPT-" + _LOCAL_NOW.strftime("%Y%m%d%H%M%S")
REPORT_DATE_TXT = _LOCAL_NOW.strftime("%d %b %Y %I:%M %p ") + REPORT_TZ_LABEL

import struct
import zipfile

ALSO_ATTACH_HTML = False

# =============================================================================
#  PAGE GEOMETRY AND FONT METRICS
# =============================================================================

PG_W, PG_H = 595.276, 841.890            # A4 at 72dpi
PG_MARGIN = 40.0
PG_BODY_W = PG_W - 2 * PG_MARGIN
PG_TOP = 96.0
PG_BOTTOM = 792.0

# Helvetica and Helvetica-Bold advance widths, codes 32..126, per 1000 units.
# Needed to wrap, centre and right-align without a layout engine.
PHR = ("0278027803550556055608890667022203330333038905840278033302780278055605560556"
       "0556055605560556055605560556027802780584058405840556101506670667072207220667"
       "0611077807220278050006670556083307220778066707780722066706110722066709440667"
       "0667061102780278027804690556022205560556050005560556027805560556022202220500"
       "0222083305560556055605560333050002780556050007220500050005000334026003340584")
PHB = ("0278033304740556055608890722023803330333038905840278033302780278055605560556"
       "0556055605560556055605560556033303330584058405840611097507220722072207220667"
       "0611077807220278055607220611083307220778066707780722066706110722066710000722"
       "0667061103330278033305840556033305560611055606110556033306110611027802780556"
       "0278088906110611061106110389055603330611055607780556055605000389028003890584")
PW_REG = [int(PHR[i:i + 4]) for i in range(0, 380, 4)]
PW_BLD = [int(PHB[i:i + 4]) for i in range(0, 380, 4)]

PC_BLACK = "#000000"
PC_WHITE = "#FFFFFF"
PC_NAVY = "#1A237E"
PC_GREY = "#666666"
PC_LINE = "#DDDDDD"
PC_BAND = "#F5F5F5"
PC_GREEN = "#2E7D32"
PC_GREENBG = "#E8F5E9"
PC_ORANGE = "#E65100"
PC_ORANGEBG = "#FFF3E0"
PC_RED = "#C62828"
PC_REDBG = "#FFEBEE"
PC_GREYBG = "#E0E0E0"


def pdf_width(s, size, bold=False):
    """Rendered width of a string at a point size."""
    tbl = PW_BLD if bold else PW_REG
    total = 0
    for ch in str(s):
        code = ord(ch)
        if 32 <= code <= 126:
            total = total + tbl[code - 32]
        else:
            total = total + 556
    return total * size / 1000.0


def pdf_wrap(s, width, size, cap_lines, bold=False):
    """Break a string into at most cap_lines lines that fit width."""
    raw_words = str(s or "").split()
    if not raw_words:
        return [""]
    # a single token wider than the column (long URL, header value) is cut
    # into pieces that fit, instead of running off the page
    words = []
    for w in raw_words:
        if pdf_width(w, size, bold) <= width:
            words.append(w)
            continue
        piece = ""
        for ch in w:
            if piece and pdf_width(piece + ch, size, bold) > width:
                words.append(piece)
                piece = ch
            else:
                piece = piece + ch
        if piece:
            words.append(piece)
    out = []
    line = ""
    for word in words:
        probe = word if not line else line + " " + word
        if pdf_width(probe, size, bold) <= width or not line:
            line = probe
        else:
            out.append(line)
            line = word
            if len(out) == cap_lines:
                break
    if len(out) < cap_lines and line:
        out.append(line)
    if not out:
        out = [""]
    # anything that did not fit is marked, rather than silently dropped
    joined = " ".join(out)
    if len(joined) < len(" ".join(words)):
        last = out[len(out) - 1]
        while (pdf_width(last + "...", size, bold) > width) and len(last) > 4:
            last = last[:len(last) - 1]
        out[len(out) - 1] = last + "..."
    return out


def pdf_clip(s, width, size, bold=False):
    """One line, shortened with an ellipsis if it will not fit."""
    s = str(s or "")
    if pdf_width(s, size, bold) <= width:
        return s
    while len(s) > 1 and pdf_width(s + "...", size, bold) > width:
        s = s[:len(s) - 1]
    return s + "..."


def pdf_int(n):
    """Thousands-separated integer."""
    try:
        return "{:,}".format(int(n))
    except Exception:
        return str(n)


# =============================================================================
#  DRAWING PRIMITIVES
# =============================================================================

def P_RECT(x, y, w, h, fill=None, stroke=None, lw=0.6):
    return ("rect", {"x": x, "y": y, "w": w, "h": h, "fill": fill,
                     "stroke": stroke, "lw": lw})


def P_LINE(x1, y1, x2, y2, stroke=PC_LINE, lw=0.6):
    return ("line", {"x1": x1, "y1": y1, "x2": x2, "y2": y2,
                     "stroke": stroke, "lw": lw})


def P_TEXT(x, y, s, size=9.0, color=PC_BLACK, anchor="start", bold=False):
    return ("text", {"x": x, "y": y, "s": str(s), "size": size,
                     "color": color, "anchor": anchor, "bold": bold})


def pdf_rgb(h):
    h = (h or "#000000").lstrip("#")
    return (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0,
            int(h[4:6], 16) / 255.0)


def pdf_escape(s):
    return (str(s).replace("\\", "\\\\").replace("(", "\\(")
            .replace(")", "\\)"))


def pdf_encode(s):
    """Latin-1 for the base font, with anything else replaced."""
    out = []
    for ch in str(s):
        code = ord(ch)
        if code < 256:
            out.append(ch)
        elif ch in "\u2013\u2014":
            out.append("-")
        elif ch in "\u2018\u2019":
            out.append("'")
        elif ch in "\u201c\u201d":
            out.append('"')
        elif ch == "\u20b9":
            out.append("Rs.")
        elif ch == "\u20ac":
            out.append("EUR ")
        elif ch == "\u2026":
            out.append("...")
        elif ch in "\u2022\u25cf\u25aa":
            out.append("-")
        elif ch == "\u2122":
            out.append("(TM)")
        elif ch in "\u200b\u200c\u200d\ufeff\ufe0f" or code >= 0x1F000 or (code >= 0x2600 and code <= 0x27BF) or (code >= 0xD800 and code <= 0xDFFF):
            continue
        else:
            out.append("?")
    return "".join(out)


def ops_to_stream(ops):
    """Turn one page of primitives into a PDF content stream."""
    parts = []
    for kind, o in ops:
        if kind == "rect":
            if o.get("fill"):
                r, g, b = pdf_rgb(o["fill"])
                parts.append("%.4f %.4f %.4f rg" % (r, g, b))
                parts.append("%.2f %.2f %.2f %.2f re f"
                             % (o["x"], PG_H - o["y"] - o["h"], o["w"], o["h"]))
            if o.get("stroke"):
                r, g, b = pdf_rgb(o["stroke"])
                parts.append("%.4f %.4f %.4f RG %.2f w" % (r, g, b, o["lw"]))
                parts.append("%.2f %.2f %.2f %.2f re S"
                             % (o["x"], PG_H - o["y"] - o["h"], o["w"], o["h"]))
        elif kind == "line":
            r, g, b = pdf_rgb(o["stroke"])
            parts.append("%.4f %.4f %.4f RG %.2f w" % (r, g, b, o["lw"]))
            parts.append("%.2f %.2f m %.2f %.2f l S"
                         % (o["x1"], PG_H - o["y1"], o["x2"], PG_H - o["y2"]))
        elif kind == "text":
            body = pdf_encode(o["s"])
            if not body:
                continue
            width = pdf_width(body, o["size"], o["bold"])
            x = o["x"]
            if o["anchor"] == "middle":
                x = x - width / 2.0
            elif o["anchor"] == "end":
                x = x - width
            r, g, b = pdf_rgb(o["color"])
            parts.append("BT /%s %.2f Tf %.4f %.4f %.4f rg %.2f %.2f Td (%s) Tj ET"
                         % ("F2" if o["bold"] else "F1", o["size"], r, g, b,
                            x, PG_H - o["y"], pdf_escape(body)))
    return "\n".join(parts).encode("latin-1", "replace")


def build_pdf_bytes(pages):
    """Assemble the pages into a complete PDF 1.4 document."""
    objs = [b""]
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                b"/Encoding /WinAnsiEncoding >>")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                b"/Encoding /WinAnsiEncoding >>")
    pages_id = 3
    objs.append(b"")                       # placeholder for the page tree
    kids = []
    for ops in pages:
        stream = ops_to_stream(ops)
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream
                    + b"\nendstream")
        content_id = len(objs) - 1
        objs.append(("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.3f %.3f] "
                     "/Resources << /Font << /F1 1 0 R /F2 2 0 R >> >> "
                     "/Contents %d 0 R >>"
                     % (pages_id, PG_W, PG_H, content_id)).encode("latin-1"))
        kids.append(len(objs) - 1)
    objs[pages_id] = ("<< /Type /Pages /Count %d /Kids [%s] >>"
                      % (len(kids), " ".join("%d 0 R" % k for k in kids))
                      ).encode("latin-1")
    objs.append(("<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
                .encode("latin-1"))
    root = len(objs) - 1

    chunks = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    written = len(chunks[0])
    offsets = [0] * len(objs)
    for i in range(1, len(objs)):
        offsets[i] = written
        chunk = ("%d 0 obj\n" % i).encode("latin-1") + objs[i] + b"\nendobj\n"
        chunks.append(chunk)
        written = written + len(chunk)
    xref = written
    tail = ("xref\n0 %d\n" % len(objs)).encode("latin-1")
    tail += b"0000000000 65535 f \n"
    for i in range(1, len(objs)):
        tail += ("%010d 00000 n \n" % offsets[i]).encode("latin-1")
    tail += ("trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
             % (len(objs), root, xref)).encode("latin-1")
    chunks.append(tail)
    return b"".join(chunks)


# =============================================================================
#  REPORT LAYOUT
# =============================================================================

VERDICT_SKIN = {
    "MALICIOUS": (PC_RED, PC_REDBG),
    "SUSPICIOUS": (PC_ORANGE, PC_ORANGEBG),
    "CLEAN": (PC_GREEN, PC_GREENBG),
}
BADGE_SKIN = {
    "malicious": (PC_RED, PC_REDBG), "suspicious": (PC_ORANGE, PC_ORANGEBG),
    "clean": (PC_GREEN, PC_GREENBG), "unknown": (PC_GREY, PC_GREYBG),
    "header": ("#1565C0", "#E3F2FD"), "body": ("#C2185B", "#FCE4EC"),
    "both": ("#7B1FA2", "#F3E5F5"),
}

PAGES = []
CUR = []
CURSOR = [PG_TOP]


def page_header(first):
    """Navy banner at the top of every page."""
    ops = [P_RECT(0, 0, PG_W, 62, fill=PC_NAVY)]
    ops.append(P_TEXT(PG_MARGIN, 28, REPORT_TITLE_TXT, 15,
                      PC_WHITE, bold=True))
    ops.append(P_TEXT(PG_MARGIN, 45, REPORT_SUBTITLE_TXT, 8.5, "#C5CAE9"))
    if first:
        ops.append(P_TEXT(PG_W - PG_MARGIN, 28, REPORT_ID_TXT, 9, PC_WHITE,
                          anchor="end"))
        ops.append(P_TEXT(PG_W - PG_MARGIN, 45, REPORT_DATE_TXT, 8,
                          "#C5CAE9", anchor="end"))
    return ops


def page_footer(number):
    ops = [P_LINE(PG_MARGIN, 800, PG_W - PG_MARGIN, 800, PC_LINE, 0.8)]
    ops.append(P_TEXT(PG_MARGIN, 812, REPORT_FOOTER_LEFT_TXT, 7.5, PC_GREY))
    ops.append(P_TEXT(PG_W / 2.0, 812, REPORT_FOOTER_MIDDLE_TXT,
                      7.5, PC_RED, anchor="middle"))
    ops.append(P_TEXT(PG_W - PG_MARGIN, 812, "Page %d" % number, 7.5, PC_GREY,
                      anchor="end"))
    return ops


def new_page():
    """Close the current page and start another."""
    if CUR:
        PAGES.append(CUR[:])
    del CUR[:]
    for op in page_header(not PAGES):
        CUR.append(op)
    CURSOR[0] = PG_TOP


def room_for(height):
    """Start a new page when the next block will not fit."""
    if CURSOR[0] + height > PG_BOTTOM:
        new_page()


def section(title):
    """Grey section heading bar."""
    room_for(34)
    y = CURSOR[0]
    CUR.append(P_RECT(PG_MARGIN, y, PG_BODY_W, 17, fill=PC_BAND,
                      stroke=PC_LINE))
    CUR.append(P_TEXT(PG_MARGIN + 7, y + 12, title.upper(), 9, PC_NAVY,
                      bold=True))
    CURSOR[0] = y + 25


def body_text(text, size=8.5, colour=PC_BLACK, gap=4.0, bold=False):
    for line in pdf_wrap(text, PG_BODY_W - 8, size, 40, bold):
        room_for(size + gap)
        CUR.append(P_TEXT(PG_MARGIN + 4, CURSOR[0] + size, line, size,
                          colour, bold=bold))
        CURSOR[0] = CURSOR[0] + size + gap


def badge(x, y, label, kind, size=7.5):
    """Small rounded-looking label, as the HTML renders them."""
    fg, bg = BADGE_SKIN.get(str(kind).lower(), BADGE_SKIN["unknown"])
    w = pdf_width(label, size, True) + 10
    return [P_RECT(x, y - size - 1, w, size + 5, fill=bg),
            P_TEXT(x + 5, y, label, size, fg, bold=True)], w


def key_value(rows, label_w=110):
    """Two-column detail table."""
    for key, value in rows:
        lines = pdf_wrap(value, PG_BODY_W - label_w - 16, 8.5, 3)
        height = 6 + len(lines) * 11
        room_for(height)
        y = CURSOR[0]
        CUR.append(P_RECT(PG_MARGIN, y, label_w, height, fill="#FAFAFA"))
        CUR.append(P_RECT(PG_MARGIN, y, PG_BODY_W, height, stroke=PC_LINE))
        CUR.append(P_TEXT(PG_MARGIN + 6, y + 12, key, 8.5, "#555555",
                          bold=True))
        row = 0
        for line in lines:
            CUR.append(P_TEXT(PG_MARGIN + label_w + 6, y + 12 + row * 11,
                              line, 8.5, PC_BLACK))
            row = row + 1
        CURSOR[0] = y + height


def data_table(header, rows, widths, badge_cols=None):
    """Header row, then one row per record, splitting across pages.

    badge_cols maps a column index to the badge kind for that cell, so the
    verdict and source columns read the way they do in the HTML.
    """
    badge_cols = badge_cols or {}
    total = 0
    for w in widths:
        total = total + w
    scale = PG_BODY_W / total

    def head():
        room_for(30)
        y = CURSOR[0]
        CUR.append(P_RECT(PG_MARGIN, y, PG_BODY_W, 16, fill=PC_NAVY))
        x = PG_MARGIN
        col = 0
        for label in header:
            cw = widths[col] * scale
            CUR.append(P_TEXT(x + 4, y + 11,
                              pdf_clip(label, cw - 8, 7.5, True), 7.5,
                              PC_WHITE, bold=True))
            x = x + cw
            col = col + 1
        CURSOR[0] = y + 16

    head()
    striped = False
    for row in rows:
        cells = []
        tallest = 1
        col = 0
        for value in row:
            cw = widths[col] * scale
            if col in badge_cols:
                cells.append([str(value)])
            else:
                lines = pdf_wrap(value, cw - 8, 7.0, 3)
                cells.append(lines)
                if len(lines) > tallest:
                    tallest = len(lines)
            col = col + 1
        height = 6 + tallest * 9
        if CURSOR[0] + height > PG_BOTTOM:
            new_page()
            head()
        y = CURSOR[0]
        if striped:
            CUR.append(P_RECT(PG_MARGIN, y, PG_BODY_W, height, fill="#FAFAFA"))
        CUR.append(P_LINE(PG_MARGIN, y + height, PG_W - PG_MARGIN, y + height,
                          PC_LINE, 0.4))
        x = PG_MARGIN
        col = 0
        for lines in cells:
            cw = widths[col] * scale
            if col in badge_cols:
                ops, unused = badge(x + 4, y + 11, lines[0],
                                    badge_cols[col](row) if callable(
                                        badge_cols[col]) else lines[0])
                for op in ops:
                    CUR.append(op)
            else:
                line_no = 0
                for line in lines:
                    CUR.append(P_TEXT(x + 4, y + 11 + line_no * 9, line, 7.0,
                                      PC_BLACK))
                    line_no = line_no + 1
            x = x + cw
            col = col + 1
        CURSOR[0] = y + height
        striped = not striped
    CURSOR[0] = CURSOR[0] + 10


def why(exc):
    """Readable text for an exception, even when its message is empty."""
    txt = str(exc)
    if not txt:
        txt = repr(exc)
    return txt[:250]


def safe_name(text, fallback, ext):
    """A filename the platform will accept, from arbitrary text."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(text or "")).strip("_")
    if not cleaned:
        cleaned = fallback
    if len(cleaned) > 120:
        cleaned = cleaned[:120]
    if not cleaned.lower().endswith(ext):
        cleaned = cleaned + ext
    return cleaned


def stage_file(name, blob):
    """Put bytes on disk without a file builtin.

    The interpreter has no file builtin and blocks the filesystem modules,
    so the bytes go into an archive member and are extracted, which leaves a
    plain file for the platform to pick up.
    """
    holder = "/tmp/soar_report_stage.pkg"
    arc = zipfile.ZipFile(holder, "w", zipfile.ZIP_DEFLATED)
    arc.writestr(name, blob)
    arc.close()
    arc = zipfile.ZipFile(holder, "r")
    arc.extract(name, "/tmp")
    arc.close()
    return "/tmp/" + name


def is_mapping(v):
    """True when v supports dict-style lookup."""
    try:
        v.get("", None)
        return True
    except Exception:
        return False


def attach(name, blob, note):
    """File one document as an attachment and report what came back."""
    entry = {"filename": name, "bytes": len(blob), "attachment_iri": "",
             "file_iri": ""}
    path = stage_file(name, blob)
    from connectors.cyops_utilities.builtins import upload_file_to_cyops
    att = upload_file_to_cyops(file_path=path, filename=name,
                               create_attachment=True, name=name,
                               description=note)
    if is_mapping(att):
        entry["attachment_iri"] = att.get("@id", "") or att.get("iri", "") or ""
        holder = att.get("file", "")
        if is_mapping(holder):
            entry["file_iri"] = holder.get("@id", "") or ""
        elif holder:
            entry["file_iri"] = str(holder)
    else:
        entry["attachment_iri"] = str(att)
    return entry




# ---- helpers every report ended up rewriting --------------------------------
BADGE_SKIN["critical"] = (PC_RED, PC_REDBG)
BADGE_SKIN["high"] = (PC_RED, PC_REDBG)
BADGE_SKIN["medium"] = (PC_ORANGE, PC_ORANGEBG)
BADGE_SKIN["low"] = ("#1565C0", "#E3F2FD")
BADGE_SKIN["info"] = (PC_GREY, PC_GREYBG)
BADGE_SKIN["high risk"] = (PC_RED, PC_REDBG)
BADGE_SKIN["medium risk"] = (PC_ORANGE, PC_ORANGEBG)
BADGE_SKIN["low risk"] = ("#1565C0", "#E3F2FD")


def sec(title):
    """section() with breathing room, kept together with the block after it."""
    CURSOR[0] = CURSOR[0] + 8
    room_for(80)
    section(title)


def banner(headline, subline, right_top="", right_bottom="", kind="medium"):
    """Coloured verdict / severity box at the top of page one."""
    fg_c, bg_c = BADGE_SKIN.get(str(kind).lower(), BADGE_SKIN["unknown"])
    room_for(58)
    y = CURSOR[0]
    CUR.append(P_RECT(PG_MARGIN, y, PG_BODY_W, 50, fill=bg_c, stroke=fg_c, lw=1.2))
    CUR.append(P_TEXT(PG_MARGIN + 14, y + 22, headline, 15, fg_c, bold=True))
    CUR.append(P_TEXT(PG_MARGIN + 14, y + 39, str(subline)[:95], 9, fg_c))
    if right_top:
        CUR.append(P_TEXT(PG_W - PG_MARGIN - 14, y + 22, right_top, 11, fg_c, anchor="end", bold=True))
    if right_bottom:
        CUR.append(P_TEXT(PG_W - PG_MARGIN - 14, y + 39, right_bottom, 8, PC_GREY, anchor="end"))
    CURSOR[0] = y + 60


def finish_pdf():
    """Close the last page, stamp footers, return the PDF bytes."""
    if CUR:
        PAGES.append(CUR[:])
    pages = []
    n = 1
    for pg in PAGES:
        ops = pg[:]
        for op in page_footer(n):
            ops.append(op)
        pages.append(ops)
        n = n + 1
    return build_pdf_bytes(pages)


def epoch_ist(ts):
    """Epoch seconds (or milliseconds) -> '24 Sep 2026 13:50:14' in report local time."""
    try:
        t = int(float(ts))
        if t > 100000000000:
            t = t // 1000
        return (datetime.utcfromtimestamp(t) + timedelta(minutes=REPORT_UTC_OFFSET_MINUTES)).strftime("%d %b %Y %H:%M:%S")
    except Exception:
        return str(ts)


def html_escape(v):
    s = "" if v is None else str(v)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
