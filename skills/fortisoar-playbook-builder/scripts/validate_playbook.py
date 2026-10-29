#!/usr/bin/env python3
"""
Validate a FortiSOAR playbook export before delivering it.

    python3 scripts/validate_playbook.py <playbook.json>

Catches the mechanical faults that make a playbook import cleanly and then
fail, or run and silently do nothing. Exits non-zero if any ERROR is found.

Delivery bar: 0 errors and 0 warnings. The only accepted exceptions are the
ones this script reports as INFO (spare placeholder steps), and anything else
you knowingly leave must be named in the delivery message.
"""
import json
import re
import sys

FIND_T = "b593663d-7d13-40ce-a3a3-96dece928770"
# Every stepType documented in reference/step-types.md and triggers.md. All of
# them were also observed across 20+ production playbooks; nothing outside this
# set appeared. An id outside it is a typo or an id-remap accident (copying a
# playbook and regenerating EVERY uuid in the file rewrites the step types too).
KNOWN_STEP_TYPES = {
    "0bfed618-0316-11e7-93ae-92361f002671", "04d0cf46-b6a8-42c4-8683-60a7eaa69e8f",
    "0109f35d-090b-4a2b-bd8a-94cbc3508562", "1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8",
    "74932bdc-b8b6-4d24-88c4-1a4dfbc524f3", "12254cf5-5db7-4b1a-8cb1-3af081924b28",
    "2597053c-e718-44b4-8394-4d40fe26d357", "f414d039-bb0d-4e59-9c39-a8f1e880b18a",
    "b348f017-9a94-471f-87f8-ce88b6a7ad62", "b593663d-7d13-40ce-a3a3-96dece928770",
    "b593663d-7d13-40ce-a3a3-96dece928722", "fc04082a-d7dc-4299-96fb-6837b1baa0fe",
    "ea155646-3821-4542-9702-b246da430a8d", "9300bf69-5063-486d-b3a6-47eb9da24872",
    "df26c7a2-4166-4ca5-91e5-548e24c01b5f", "a19333c2-c822-11ed-afa1-0242ac120002",
    "dc6ac63d-c5a5-472f-9eb4-6b18473a98b8", "7b221880-716b-4726-a2ca-5e568d330b3e",
    "6832e556-b9c7-497a-babe-feda3bd27dbf", "4c0019b2-055c-44d0-968c-678a0c2d762e",
}
# Connector names / operations that mean "look something up", as opposed to
# act on something (block, ticket, mail). Only these make a playbook an
# enrichment playbook for the verdict / ignore_errors checks.
ENRICH_HINTS = ("fortiguard", "virustotal", "abuseipdb", "threat_intel", "reputation",
                "ip_lookup", "query_ip", "query_url", "query_domain", "query_file",
                "whois", "urlscan", "greynoise", "shodan", "alienvault", "otx", "misp",
                "anomali", "recorded", "hybrid", "sandbox", "ioc_lookup", "get_indicator")
# Keys a Set Variable step can carry that are step controls, not variables.
CONTROL_KEYS = ("step_variables", "__recommend", "when", "for_each", "ignore_errors",
                "mock_result", "_showJson", "message")


try:
    import jinja2
    JINJA_ENV = jinja2.Environment()
except Exception:                      # jinja2 not installed - skip that check
    JINJA_ENV = None


def _templates(node, where):
    """every string under node that contains jinja, with a readable path"""
    if isinstance(node, str):
        if "{{" in node or "{%" in node:
            yield where, node
    elif isinstance(node, dict):
        for k, v in node.items():
            for x in _templates(v, (where + "." + str(k)) if where else str(k)):
                yield x
    elif isinstance(node, list):
        for v in node:
            for x in _templates(v, where):
                yield x


def is_enrichment(args):
    blob = ("%s %s %s" % (args.get("connector", ""), args.get("operation", ""),
                          args.get("name", ""))).lower()
    return any(h in blob for h in ENRICH_HINTS)


def is_placeholder(step):
    blob = ("%s %s" % (step.get("name", ""), step.get("description") or "")).lower()
    return any(w in blob for w in ("spare", "placeholder", "dummy"))
BANNED = ["set", "any", "all", "enumerate", "sum", "type", "eval",
          "exec", "open", "reversed", "map", "filter", "max", "min"]
ALLOWED_NOTE = ("list dict tuple str int float bool len sorted zip abs "
                "round isinstance range print")

errors = []
warns = []
oks = []
infos = []


def err(m):
    errors.append(m)


def warn(m):
    warns.append(m)


def ok(m):
    oks.append(m)


def strip_literals(src):
    """Remove comments, docstrings and string literals so builtin detection
    only looks at real code. The connector matches source text including
    comments, so we check those separately."""
    s = re.sub(r'"""(?:.|\n)*?"""', '', src)
    s = re.sub(r"'''(?:.|\n)*?'''", '', s)
    s = re.sub(r'#[^\n]*', '', s)
    s = re.sub(r'"(?:[^"\\]|\\.)*"', '""', s)
    s = re.sub(r"'(?:[^'\\]|\\.)*'", "''", s)
    return s


def check_code(name, src):
    code = strip_literals(src)
    for b in BANNED:
        if re.search(r'(?<![\w.])' + b + r'\s*\(', code):
            err("%s: uses banned builtin %s()" % (name, b))
    # Measured on the appliance: the sandbox rejects the CALL, not the text.
    # A banned word in a comment, string or identifier executes fine, so no
    # comment scan here. sorted/zip/abs/round are ALLOWED - they were wrongly
    # listed as banned before v2.4 and must not be flagged.
    #
    # isinstance(x, list) is INSTANCE-DEPENDENT. On the lab appliance `list`
    # is a shim and this raises TypeError, killing the step. On two production
    # instances it runs fine (measured: playbooks that returned output). A
    # playbook that may be imported anywhere should use the portable form.
    if re.search(r'isinstance\s*\([^)]*,\s*list\s*\)', code):
        warn("%s: isinstance(x, list) raises on some FortiSOAR sandboxes (works "
             "on others). For a portable playbook branch on isinstance(x, dict) "
             "first and otherwise iterate inside a try, or bind "
             "LIST_T = builtins.list once and use isinstance(x, LIST_T)" % name)
    if re.search(r'(?<![\w.])lambda\b', code):
        err("%s: uses lambda - write an explicit loop or insertion sort" % name)
    if "true, false, null" not in src and "{{" in src:
        warn("%s: injects jinja but does not alias true/false/null" % name)
    n_print = len(re.findall(r'(?<![\w.])print\s*\(', src))
    if n_print == 0:
        warn("%s: no print() - a code snippet must emit its result" % name)
    elif n_print > 1:
        warn("%s: %d print() calls - only the last line is read downstream"
             % (name, n_print))
    if "{{vars.result}}" in src or "{{ vars.result }}" in src:
        warn("%s: references vars.result inside the code. vars.result is only "
             "the step's own output inside that step's step_variables - read "
             "another step as vars.steps.<Name> instead" % name)
    # FortiSOAR's urlencode encodes a space as '+'. Measured on production:
    # json.loads(unquote("{{ x | tojson | urlencode }}")) failed with a 400
    # JSONDecodeError at the first space. unquote_plus is required (pitfall 43).
    if ("urlencode" in src and re.search(r'(?<![\w.])unquote\s*\(', code)
            and not re.search(r'unquote_plus\s+as\s+unquote\b', src)):
        warn("%s: decodes urlencode output with unquote() - FortiSOAR's urlencode "
             "turns spaces into '+', so the JSON fails to parse. Use "
             "urllib.parse.unquote_plus (pitfall 43)" % name)
    # The whole alert/sourcedata rendered into the code is a request-size
    # problem: a 2.3 MB sourcedata made the code-snippet call fail with a bare
    # "Server Error (500)" and no traceback. Trim in jinja first.
    if re.search(r'vars\.input\.records\[0\](?:\.sourcedata)?\s*(?:\|[^}]*)?\}\}', src):
        warn("%s: renders the whole record / sourcedata into the code. Large "
             "alerts (emails with inline images, wrapped originals) exceed the "
             "code-snippet request size and fail with a bare 500 - build a "
             "trimmed dict in jinja and pass only the fields you read" % name)


def check_cond(label, cond, template=False):
    if cond.count("(") != cond.count(")"):
        err("%s: unbalanced parentheses in cond" % label)
    if cond.count('"') % 2:
        err("%s: odd number of double quotes in cond" % label)
    if re.search(r'(?<!\\)\\"', cond):
        err("%s: backslash immediately before a closing quote - the string "
            "never terminates and the query is rejected with a 400" % label)
    # A cond inside a plan-building snippet is a Python source literal, so a
    # doubled backslash there renders to a single one. Only flag it on a cond
    # taken straight from a connector step.
    if template:
        return
    if "\\\\" in cond:
        warn("%s: doubled backslash in cond - usually matches nothing" % label)
    if "customer" not in cond:
        warn("%s: no customer/tenant scope in cond" % label)


def main(path):
    doc = json.load(open(path, encoding="utf-8"))
    colls = doc.get("data") or []
    if not colls:
        err("no collections in data[]")
        return
    # every workflow in the file, so a Reference-a-Playbook step can be checked
    # against the playbook it calls when both travel together
    all_wfs = {}
    for c0 in colls:
        for w0 in (c0.get("workflows") or []):
            all_wfs[str(w0.get("uuid"))] = w0

    for coll in colls:
        cuuid = coll.get("uuid")
        for wf in (coll.get("workflows") or []):
            name = wf.get("name", "?")
            steps = wf.get("steps") or []
            routes = wf.get("routes") or []
            byuuid = {s["uuid"]: s for s in steps}
            names = {s["name"]: s for s in steps}

            # A single-playbook export keeps the workflow pointed at its real
            # home collection, not at the synthetic wrapper in the file, so a
            # mismatch is normal there. It is only a fault on a playbook built
            # from scratch, which is identifiable by null identity fields.
            if wf.get("collection") and cuuid and cuuid not in str(wf.get("collection")):
                newly_built = wf.get("id") is None and wf.get("createDate") is None
                if newly_built:
                    err("%s: workflow.collection does not reference the parent "
                        "collection uuid" % name)
                else:
                    warn("%s: workflow.collection points at a different collection "
                         "than the parent - normal for a real single-playbook "
                         "export, leave as-is unless this is a new playbook" % name)

            # --- every jinja template must parse ---
            # A syntax error here passes every structural check and then fails
            # the step on every run. Observed: `(x | default({}, true)).data |
            # default({}, true).IP` - an unparenthesised filter chain.
            # FortiSOAR renders code snippets as templates too, so they count.
            if JINJA_ENV is not None:
                for s in steps:
                    for where, tpl in _templates(s.get("arguments") or {}, ""):
                        try:
                            JINJA_ENV.parse(tpl)
                        except Exception as exc:
                            err("%s: step '%s' has a jinja syntax error in %s: %s"
                                % (name, s.get("name"), where or "arguments",
                                   str(exc).split("\n")[0][:120]))

            # --- step types must be real ---
            for s in steps:
                st = str(s.get("stepType", "")).split("/")[-1]
                if st and st not in KNOWN_STEP_TYPES:
                    err("%s: step '%s' has an unknown stepType %s - a typo, or every "
                        "uuid in the file was regenerated when copying a playbook. "
                        "Only a playbook's OWN ids (collection, workflow, steps, "
                        "routes) may be replaced" % (name, s.get("name"), st))

            # --- sub-playbook arguments must match what the target declares ---
            # Block playbooks for different clients take different argument
            # names for the same thing (DomianList vs Domain_List, Ticket vs
            # Ticket_id). A misspelt argument is not an error to FortiSOAR -
            # the child simply receives nothing and "succeeds".
            for s in steps:
                a = s.get("arguments") or {}
                ref = str(a.get("workflowReference") or "").split("/")[-1]
                if not ref:
                    continue
                target = all_wfs.get(ref)
                if target is None:
                    continue
                declared_params = [str(x.get("name") if isinstance(x, dict) else x)
                                   for x in (target.get("parameters") or [])]
                if not declared_params:
                    continue
                passed = list((a.get("arguments") or {}).keys())
                for arg in passed:
                    if arg not in declared_params:
                        err("%s: step '%s' passes '%s' to '%s', which declares only %s "
                            "- the child receives nothing for it"
                            % (name, s.get("name"), arg, target.get("name"), declared_params))
                for prm in declared_params:
                    if prm not in passed:
                        warn("%s: step '%s' does not pass '%s' to '%s'"
                             % (name, s.get("name"), prm, target.get("name")))

            # --- a manual input copied from another playbook ---
            # message.parentstepid is rewritten by FortiSOAR on import; copied
            # into a different playbook it points at a step that is not here.
            for s in steps:
                if "fc04082a-d7dc-4299-96fb-6837b1baa0fe" not in str(s.get("stepType", "")):
                    continue
                pid = str(((s.get("arguments") or {}).get("message") or {}).get("parentstepid") or "")
                if pid and pid.split("/")[-1] not in byuuid:
                    warn("%s: manual input '%s' has message.parentstepid pointing at a "
                         "step that is not in this playbook (copied from another one?) "
                         "- remove the key and FortiSOAR sets it on import"
                         % (name, s.get("name")))

            # --- naming ---
            for s in steps:
                if re.search(r'[^\w ]', s["name"]):
                    err("%s: step name '%s' has characters other than word chars "
                        "and spaces - jinja references will break" % (name, s["name"]))

            # --- routes ---
            srcs = {}
            tgts = {}
            for r in routes:
                srcs[str(r.get("sourceStep", "")).split("/")[-1]] = True
                tgts[str(r.get("targetStep", "")).split("/")[-1]] = True
                for k in ("sourceStep", "targetStep"):
                    u = str(r.get(k, "")).split("/")[-1]
                    if u and u not in byuuid:
                        err("%s: route '%s' %s points at a uuid with no step"
                            % (name, r.get("name"), k))
            for s in steps:
                a = s.get("arguments") or {}
                # A no_op with no outgoing route is a deliberate single
                # exit point, not a dead end. Warning on it trains people to
                # ignore warnings, which is where the real ones hide.
                is_noop = (a.get("operation") == "no_op")
                # A SetVariable that several branches converge into is the
                # result contract the skill asks for - it is SUPPOSED to be the
                # last step. Flagging it trains people to ignore warnings,
                # which is where the real ones hide.
                SETVAR = "04d0cf46-b6a8-42c4-8683-60a7eaa69e8f"
                is_setvar = SETVAR in str(s.get("stepType", ""))
                has_incoming = s["uuid"] in tgts
                lname = s["name"].lower()
                is_terminal = (a.get("arguments") or a.get("Result") is not None
                               or is_noop
                               or "result" in lname
                               or (is_setvar and has_incoming))
                if s["uuid"] not in srcs and not is_terminal:
                    if not has_incoming and is_placeholder(s):
                        infos.append("%s: '%s' is an unattached placeholder - fine "
                                     "if intentional, mention it on delivery"
                                     % (name, s["name"]))
                    else:
                        warn("%s: step '%s' has no outgoing route - dead end?"
                             % (name, s["name"]))

            trig = str(wf.get("triggerStep", "")).split("/")[-1]
            if trig and trig not in byuuid:
                err("%s: triggerStep does not match any step" % name)

            # --- injected dict keys vs the keys the code reads ---
            # A jinja loop builds a list of dict literals with one set of keys,
            # then the python below indexes a different set. Nothing catches it
            # until the step dies with KeyError and the run stops. Observed: a
            # loop building {value, ticket_missing, firewall_missing} whose code
            # then read record['ticket'], record['firewall'] and record['id'].
            for s3 in steps:
                code3 = ((s3.get("arguments") or {}).get("params")
                         or {}).get("python_function") or ""
                if "{%" not in code3 or "for " not in code3:
                    continue
                built = set()
                for m3 in re.finditer(r"\{%\s*for\b[^%]*%\}(.{0,4000}?)\{%\s*endfor",
                                      code3, re.S):
                    built.update(re.findall(r'"(\w+)"\s*:', m3.group(1)))
                if not built:
                    continue
                # Only the PYTHON counts. A key inside a {{ }} or {% %}
                # region is jinja - vars.steps.X.data['code_output'] is not
                # a python dict access, and flagging it is a false positive.
                py_only = re.sub(r'\{\{.*?\}\}', ' ', code3, flags=re.S)
                py_only = re.sub(r'\{%.*?%\}', ' ', py_only, flags=re.S)
                read = set()
                for m3 in re.finditer(r'\b\w+\[[\'\"](\w+)[\'\"]\]', py_only):
                    read.add(m3.group(1))
                # a key assigned elsewhere in python is fine
                assigned = set(re.findall(r"['\"](\w+)['\"]\s*:", code3))
                missing = sorted(k for k in read
                                 if k not in built and k not in assigned)
                if missing:
                    err("%s: step '%s' reads key(s) %s that the jinja loop never "
                        "builds - it constructs %s. A missing key is a KeyError "
                        "and the step dies at run time"
                        % (name, s3["name"], ", ".join(repr(k) for k in missing),
                           ", ".join(sorted(built))[:80]))

            # --- Find Records page size lives in the module string ---
            # query.limit is ignored by the engine. A step asking for 500 rows
            # through query.limit silently gets 30, and every count downstream
            # is then drawn from 6% of the module.
            for s4 in steps:
                if FIND_T not in str(s4.get("stepType", "")):
                    continue
                a4 = s4.get("arguments") or {}
                mod = str(a4.get("module") or "")
                qlim = ((a4.get("query") or {}).get("limit"))
                try:
                    qlim = int(qlim)
                except (TypeError, ValueError):
                    qlim = None
                if "$limit" in mod:
                    continue
                if qlim is not None and qlim != 30:
                    err("%s: step '%s' sets query.limit=%s but its module string "
                        "is '%s' with no $limit - query.limit is ignored and the "
                        "step returns the default 30 rows. Put the size in the "
                        "module: '%s?$limit=%s'"
                        % (name, s4["name"], qlim, mod, mod.split("?")[0], qlim))
                else:
                    warn("%s: step '%s' has no $limit in its module string ('%s'), "
                         "so it returns the default 30 rows whatever query.limit "
                         "says. State the size where it is read: '%s?$limit=N'"
                         % (name, s4["name"], mod, mod.split("?")[0]))

            # --- coverage claims must not be len(rows) over len(rows) ---
            for s4 in steps:
                code4 = ((s4.get("arguments") or {}).get("params")
                         or {}).get("python_function") or ""
                if not code4:
                    continue
                low4 = code4.lower()
                claims = ("of {} available" in low4 or "available" in low4
                          and "examined" in low4)
                if not claims:
                    continue
                if re.search(r"(total|available)\w*\s*=\s*len\(", code4):
                    warn("%s: step '%s' reports a coverage figure whose "
                         "denominator is len(rows) - a Find Records step returns "
                         "no population count, so that renders as 'N of N' and "
                         "claims a full sweep of whatever page it got"
                         % (name, s4["name"]))

            # --- canvas overlap ---
            # "the boxes overlap and it is unreadable" is the single most
            # common complaint about a generated playbook, and every other
            # check in this file passes a canvas where two steps sit on top of
            # each other. A step renders roughly 200x60, so anything closer
            # than 240 across / 90 down collides.
            pos = []
            for s3 in steps:
                try:
                    pos.append((int(s3.get("top") or 0), int(s3.get("left") or 0),
                                s3.get("name")))
                except (TypeError, ValueError):
                    continue
            for i3 in range(len(pos)):
                for j3 in range(i3 + 1, len(pos)):
                    dt = abs(pos[i3][0] - pos[j3][0])
                    dl = abs(pos[i3][1] - pos[j3][1])
                    if dt < 90 and dl < 240:
                        # a hand-laid-out production export that overlaps still
                        # runs; only a playbook built from scratch is held to it
                        report = err if (wf.get("id") is None and wf.get("createDate") is None) else warn
                        report("%s: steps '%s' and '%s' overlap on the canvas "
                            "(top differs by %d, left by %d). Keep them at least "
                            "90 apart vertically or 240 horizontally (150 / 260 "
                            "reads comfortably)"
                            % (name, pos[i3][2], pos[j3][2], dt, dl))

            # --- substance: is this playbook actually useful? ---
            # These fire only where they apply, so a deliberately simple
            # reporting playbook is not nagged. They exist because every other
            # check in this file passes a playbook that runs fine and tells an
            # analyst nothing.
            CONN_T3 = "0bfed618-0316-11e7-93ae-92361f002671"
            INPUT_T3 = "fc04082a-d7dc-4299-96fb-6837b1baa0fe"
            code_all = " ".join(
                str(((s3.get("arguments") or {}).get("params") or {}).get(
                    "python_function") or "") for s3 in steps).lower()
            enriches = any(CONN_T3 in str(s3.get("stepType", "")) and
                           is_enrichment(s3.get("arguments") or {}) for s3 in steps)

            if enriches and code_all:
                if not any(w in code_all for w in
                           ("verdict", "classification", "disposition", "assessment")):
                    warn("%s: it enriches indicators but never assigns a verdict. "
                         "An analyst gets scores with no conclusion - give each "
                         "indicator a disposition" % name)
                elif not any(w in code_all for w in
                             ("reason", "rationale", "because", "evidence", "detail")):
                    warn("%s: verdicts are assigned but no reasoning is recorded. "
                         "An analyst cannot tell why an indicator was judged the "
                         "way it was" % name)

            for s3 in steps:
                if INPUT_T3 not in str(s3.get("stepType", "")):
                    continue
                body = (((s3.get("arguments") or {}).get("input") or {})
                        .get("schema") or {}).get("description") or ""
                if not body:
                    continue
                if "**" in body and "<" not in body:
                    warn("%s: the manual input '%s' description uses markdown "
                         "(**bold**). It is rendered as HTML, so the markdown "
                         "shows as literal characters - build it in HTML" % (name, s3["name"]))
                # A body that renders HTML built upstream (e.g. a code step's
                # decision_html) is a real report, not a static blurb.
                prebuilt = re.search(r'\{\{[^}]*html[^}]*\}\}', body, re.I)
                if "{%" not in body and "<table" not in body.lower() and not prebuilt:
                    warn("%s: the analyst body on '%s' renders no table and no "
                         "loop - it is a static blurb or a raw dump. Build the "
                         "findings into a readable report" % (name, s3["name"]))

            # --- date filters must be ISO strings, never epochs ---
            # createDate holds an epoch float, so filtering it with a number is
            # the obvious move and it is wrong: the query API returns a
            # DriverException 400 whose message says only "Internal Server
            # Error". Only "2026-08-01" style values work.
            DATEISH = ("createdate", "modifydate", "date", "time")
            for s2 in steps:
                q2 = (s2.get("arguments") or {}).get("query")
                if not isinstance(q2, dict):
                    continue
                for f2 in (q2.get("filters") or []):
                    if not isinstance(f2, dict):
                        continue
                    fld = str(f2.get("field") or "")
                    if not any(d in fld.lower() for d in DATEISH):
                        continue
                    val = f2.get("value")
                    bad = False
                    if isinstance(val, bool):
                        bad = False
                    elif isinstance(val, (int, float)):
                        bad = True
                    elif isinstance(val, str):
                        low = val.lower()
                        if any(k in low for k in ("timestamp()", "epoch", ".now()")):
                            bad = True
                        else:
                            try:
                                float(val)
                                bad = True
                            except ValueError:
                                bad = False
                    if bad:
                        err("%s: step '%s' filters '%s' with an epoch value "
                            "(%.60s). The query API rejects numbers on date "
                            "fields with a DriverException 400 - use an ISO "
                            "string such as \"2026-08-01\""
                            % (name, s2["name"], fld, str(val)))

            # --- Find Records has no .data ---
            # It returns the list directly at vars.steps.<Name>. Reading
            # .data yields nothing, and a `| default([])` beside it turns that
            # into a clean empty list - so the playbook runs green, finds
            # nothing, and takes its own empty-batch path.
            find_names = set()
            for s2 in steps:
                if "b593663d-7d13-40ce-a3a3-96dece928770" in str(s2.get("stepType", "")):
                    find_names.add(re.sub(r"\W", "_", str(s2.get("name") or "")))
            wfblob2 = json.dumps(wf)
            for fname in sorted(find_names):
                # also the guarded form: (vars.steps.X | default({}, true)).data
                if re.search(r"vars\.steps\." + re.escape(fname) + r"(\s*\|[^)]*\))?\s*\)*\s*\.data\b", wfblob2):
                    err("%s: '%s' is a Find Records step - it returns the list "
                        "directly, so vars.steps.%s.data resolves to nothing. "
                        "Drop the .data (a `| default([])` next to it will hide "
                        "this as an empty result)" % (name, fname, fname))

            # --- numeric query fields must be numbers ---
            # A jinja string in query.limit is accepted and then ignored: the
            # query silently returns the 30-record ceiling instead of the cap.
            for s2 in steps:
                q2 = (s2.get("arguments") or {}).get("query")
                if not isinstance(q2, dict):
                    continue
                lim = q2.get("limit")
                if isinstance(lim, str):
                    err("%s: step '%s' has query.limit as the string %r. It is "
                        "ignored and the query returns the 30-record ceiling. "
                        "Use an integer literal" % (name, s2["name"], lim))

            # --- step type must match the argument shape ---
            # b593663d-...928770 is FindRecords and ...928722 is UpdateRecord.
            # They differ in the last two digits and are easy to transpose. A
            # step carrying query+module arguments under the UpdateRecord type
            # is not a read - it is a write step, and it will not do what the
            # playbook intends.
            UPD_T = "b593663d-7d13-40ce-a3a3-96dece928722"
            for s2 in steps:
                a2 = s2.get("arguments") or {}
                stype2 = str(s2.get("stepType", ""))
                if "query" in a2 and "module" in a2 and FIND_T not in stype2:
                    what = ("UpdateRecord - a WRITE step" if UPD_T in stype2
                            else "not FindRecords")
                    err("%s: step '%s' has Find Records arguments (query + "
                        "module) but its stepType is %s. Use %s"
                        % (name, s2["name"], what, FIND_T))

            # --- three defects that survive every generation ---
            CONN_T2 = "0bfed618-0316-11e7-93ae-92361f002671"
            DEC_T2 = "12254cf5-5db7-4b1a-8cb1-3af081924b28"
            INPUT_T2 = "fc04082a-d7dc-4299-96fb-6837b1baa0fe"

            # 1. an enrichment loop that aborts the batch on one bad lookup
            for s2 in steps:
                if CONN_T2 not in str(s2.get("stepType", "")):
                    continue
                a2 = s2.get("arguments") or {}
                loops = bool(((a2.get("for_each") or {}) if isinstance(a2.get("for_each"), dict) else {}).get("item"))
                if not (is_enrichment(a2) or loops):
                    continue
                if not a2.get("ignore_errors"):
                    warn("%s: '%s' has ignore_errors unset - one failed lookup "
                         "aborts the whole run. Set it true on enrichment steps "
                         "unless a failure genuinely must stop the playbook"
                         % (name, s2["name"]))

            # 2. independent enrichment chained instead of fanned out
            byu2 = {s2["uuid"]: s2 for s2 in steps}
            outgoing = {}
            for r in routes:
                outgoing.setdefault(
                    str(r.get("sourceStep", "")).rsplit("/", 1)[-1], []).append(
                    str(r.get("targetStep", "")).rsplit("/", 1)[-1])
            for s2 in steps:
                if CONN_T2 not in str(s2.get("stepType", "")):
                    continue
                fe_a = ((s2.get("arguments") or {}).get("for_each") or {})
                for tgt in outgoing.get(s2["uuid"], []):
                    t2 = byu2.get(tgt)
                    if not t2 or CONN_T2 not in str(t2.get("stepType", "")):
                        continue
                    # The second step is only genuinely sequential if it
                    # actually consumes the first. If it never references it,
                    # the chain is gratuitous and costs a full round of lookups.
                    fe_b = ((t2.get("arguments") or {}).get("for_each") or {})
                    ref_a = re.sub(r"\W", "_", str(s2.get("name") or ""))
                    consumes = ("vars.steps." + ref_a) in json.dumps(
                        t2.get("arguments") or {})
                    # Looping the SAME list proves independence outright - an
                    # incidental reference elsewhere in the arguments (a
                    # step_variables roll-up, say) must not mask that.
                    same_list = (str(fe_a.get("item") or "").strip()
                                 and fe_a.get("item") == fe_b.get("item"))
                    if same_list or not consumes:
                        why = ("both loop over the same list"
                               if same_list else
                               "'%s' never reads it" % t2["name"])
                        warn("%s: '%s' runs before '%s' but %s, so the wait "
                             "buys nothing. Fan both out from their shared "
                             "parent and converge on the next step"
                             % (name, s2["name"], t2["name"], why))

            # 3. a manual input with nothing guarding an empty batch
            has_input = any(INPUT_T2 in str(s2.get("stepType", ""))
                            for s2 in steps)
            has_dec = any(DEC_T2 in str(s2.get("stepType", ""))
                          for s2 in steps)
            if has_input and not has_dec:
                warn("%s: there is a manual input but no Decision step. If the "
                     "batch comes back empty the analyst is asked to review "
                     "nothing. Guard it and give the empty path its own route "
                     "to the result step" % name)

            # --- connector-backed steps need the full envelope ---
            # A Code Snippet is a Connector step underneath. Giving it only
            # params.python_function yields "retrieving the connector operation
            # None" at run time. Static structure looks fine; the step is dead.
            CODE_T = "1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8"
            CONN_T = "0bfed618-0316-11e7-93ae-92361f002671"
            for s2 in steps:
                stype = str(s2.get("stepType", ""))
                a2 = s2.get("arguments") or {}
                is_code = CODE_T in stype
                is_conn = CONN_T in stype
                if not (is_code or is_conn):
                    continue
                for field in ("connector", "operation", "version", "config"):
                    # an empty config is a deliberate "use the default" (reported
                    # as INFO elsewhere); only a missing key is an error
                    if field == "config" and "config" in a2:
                        continue
                    if not str(a2.get(field) or "").strip():
                        err("%s: step '%s' is missing '%s' - a %s step needs the "
                            "full connector envelope (connector, operation, "
                            "version, config) or it fails at run time"
                            % (name, s2["name"], field,
                               "Code Snippet" if is_code else "Connector"))
                if is_code:
                    if a2.get("connector") not in (None, "", "code-snippet"):
                        err("%s: step '%s' has stepType CodeSnippet but "
                            "connector=%r" % (name, s2["name"], a2.get("connector")))
                    if (a2.get("operation") not in
                            (None, "", "python_inline_code_editor")):
                        err("%s: step '%s' operation should be "
                            "'python_inline_code_editor', got %r"
                            % (name, s2["name"], a2.get("operation")))

            # --- parallel for_each results are not in input order ---
            # A for_each with parallel:true returns results in COMPLETION
            # order. Aligning them to the input list by index silently attaches
            # each enrichment to the wrong indicator. Measured: 6 of 10 scores
            # landed on the wrong IP, and the report looked entirely plausible.
            par = set()
            for s2 in steps:
                fe = (s2.get("arguments") or {}).get("for_each")
                if isinstance(fe, dict) and fe.get("parallel") is True:
                    par.add(re.sub(r"\W", "_", str(s2.get("name") or "")))
            for s2 in steps:
                code2 = ((s2.get("arguments") or {}).get("params")
                         or {}).get("python_function") or ""
                if not code2:
                    continue
                for pname in sorted(par):
                    if ("vars.steps." + pname) not in code2:
                        continue
                    if re.search(r"\[\s*(i|idx|index|n|pos)\s*\]", code2):
                        err("%s: '%s' consumes the parallel for_each step '%s' "
                            "by positional index. Parallel results come back in "
                            "completion order, so the enrichment attaches to the "
                            "wrong item. Set parallel:false, or join on a value "
                            "the response echoes back (e.g. ipAddress)"
                            % (name, s2["name"], pname))
                    else:
                        warn("%s: '%s' reads the parallel for_each step '%s' - "
                             "make sure it joins on an echoed value, not order"
                             % (name, s2["name"], pname))

            # --- an empty for_each block is runtime-fatal ---
            # A step carrying "for_each": {"item": "", ...} dies immediately
            # with CS-WF-3: Invalid format of value for for_each loop ''.
            # Editors leave this stub behind on steps that never needed a loop,
            # and nothing about it looks wrong in the JSON. Three separately
            # generated playbooks all carried it on their Find Records step and
            # all three died on that step.
            for s2 in steps:
                fe = (s2.get("arguments") or {}).get("for_each")
                if not isinstance(fe, dict):
                    continue
                if not str(fe.get("item") or "").strip():
                    err("%s: step '%s' has a for_each block with an empty "
                        "'item' - this fails at run time with CS-WF-3. Remove "
                        "the whole for_each key if the step does not loop"
                        % (name, s2["name"]))

            # --- Set Variable keys that nothing ever reads ---
            # A Configuration step whose variables no snippet reads is worse
            # than no Configuration step: the playbook LOOKS parameterised,
            # the user edits the threshold there, and nothing changes. Seen in
            # a generated playbook where all three config variables were dead
            # and the code hardcoded the same values.
            SETVAR_T = "04d0cf46-b6a8-42c4-8683-60a7eaa69e8f"
            declared = {}
            for s2 in steps:
                if SETVAR_T not in str(s2.get("stepType", "")):
                    continue
                # The terminal result contract is deliberately not read inside
                # the playbook - it exists for whatever consumes the run.
                if s2["uuid"] not in srcs:
                    continue
                if is_placeholder(s2):
                    continue
                for k in (s2.get("arguments") or {}):
                    if k in CONTROL_KEYS:
                        continue
                    declared.setdefault(k, s2["name"])
            wfblob = json.dumps(wf)
            for k, owner in sorted(declared.items()):
                if re.search(r"vars\.%s\b" % re.escape(k), wfblob):
                    continue
                warn("%s: '%s' is set by '%s' but never read - if the code "
                     "hardcodes this value instead, editing the step does "
                     "nothing" % (name, k, owner))

            # --- jinja step references must resolve ---
            # A space in a step NAME becomes an underscore in the REFERENCE.
            # Writing vars.steps.Get Oldest Blocked IPs does not raise - it
            # yields nothing, and the playbook runs green having done nothing.
            # An external AI produced a playbook where all seven references
            # carried literal spaces and this validator passed it 0/0.
            valid_refs = set()
            for s in steps:
                valid_refs.add(re.sub(r"\W", "_", str(s.get("name") or "")))
            blob = json.dumps(wf)
            seen_bad = set()
            for m in re.finditer(r"vars\.steps\.([A-Za-z0-9_]+)", blob):
                ref = m.group(1)
                if ref in valid_refs:
                    continue
                if ref in seen_bad:
                    continue
                seen_bad.add(ref)
                # A valid name that this ref is a strict prefix of means the
                # reference was cut short by a space in the step name.
                trunc = [v for v in valid_refs if v.startswith(ref + "_")]
                if trunc:
                    err("%s: jinja reference 'vars.steps.%s' is truncated - the "
                        "step name contains spaces, so the reference must use "
                        "underscores: 'vars.steps.%s'" % (name, ref, trunc[0]))
                else:
                    err("%s: jinja reference 'vars.steps.%s' matches no step"
                        % (name, ref))

            # --- decisions ---
            for s in steps:
                a = s.get("arguments") or {}
                for c in (a.get("conditions") or []):
                    tu = str(c.get("step_iri", "")).split("/")[-1]
                    if tu and tu not in byuuid:
                        err("%s: decision '%s' condition targets a missing step"
                            % (name, s["name"]))
                    elif tu and not any(
                            str(r.get("sourceStep", "")).split("/")[-1] == s["uuid"]
                            and str(r.get("targetStep", "")).split("/")[-1] == tu
                            for r in routes):
                        err("%s: decision '%s' has a condition with no matching route"
                            % (name, s["name"]))

            # --- connector config / version / step variables ---
            for s in steps:
                a = s.get("arguments") or {}
                sn = s["name"]
                if a.get("connector") and a.get("name"):
                    raw_cfg = a.get("config")
                    cfg = str(raw_cfg or "")
                    if "config" not in a:
                        err("%s: connector step '%s' has no config key" % (name, sn))
                    elif cfg in ("", "''", '""'):
                        # An empty config means "this instance's default
                        # configuration" - what Fortinet's own sample playbooks
                        # use, and what makes a playbook portable between
                        # instances. Wrong only where the config selects a
                        # client's device (MSSP response connectors).
                        infos.append("%s: '%s' uses the instance's default configuration "
                                     "(empty config) - portable; confirm a default exists, "
                                     "and never rely on it for a per-client response connector"
                                     % (name, sn))
                    elif cfg.startswith("<") or "SELECT" in cfg.upper():
                        warn("%s: connector step '%s' still has a placeholder config "
                             "(%s) - ask the user for the real uuid" % (name, sn, cfg))
                    if not a.get("version"):
                        warn("%s: connector step '%s' has no version" % (name, sn))
                sv = a.get("step_variables")
                if isinstance(sv, dict):
                    for k, v in sv.items():
                        v = str(v)
                        if "vars.result" in v and a.get("connector") in (None, "", "code-snippet"):
                            warn("%s: step '%s' variable '%s' uses vars.result. On a "
                                 "connector step that is its own output (verified in "
                                 "production); on this step type read "
                                 "vars.steps.%s instead" % (name, sn, k, sn.replace(" ", "_")))
                        m = re.search(r'vars\.steps\.([\w ]+)', v)
                        if m:
                            ref = m.group(1).strip()
                            # a space in a step NAME is an underscore in the
                            # reference - compare like with like
                            known_refs = set(names) | {n.replace(" ", "_") for n in names}
                            if ref not in known_refs:
                                err("%s: step '%s' variable '%s' references unknown "
                                    "step '%s'" % (name, sn, k, ref))
                            elif ref != sn and a.get("params") is not None and \
                                    a.get("connector") is None:
                                warn("%s: step '%s' variable '%s' reads step '%s' - "
                                     "correct only if deliberate (cloned step?)"
                                     % (name, sn, k, ref))

            # --- code snippets ---
            for s in steps:
                a = s.get("arguments") or {}
                p = a.get("params") or {}
                src = p.get("python_function") if isinstance(p, dict) else None
                if src:
                    check_code("%s / %s" % (name, s["name"]), src)
                    for m in re.finditer(r'"cond":\s*\'(.*?)\',\n', src, re.S):
                        check_cond("%s / %s cond" % (name, s["name"]), m.group(1), True)

            # --- inline connector conds ---
            for s in steps:
                a = s.get("arguments") or {}
                p = a.get("params") or {}
                if isinstance(p, dict) and isinstance(p.get("cond"), str) \
                        and "{{" not in p["cond"]:
                    check_cond("%s / %s" % (name, s["name"]), p["cond"])

            # --- native steps first: keep the code-snippet count visible ---
            # Upgrades tighten the sandbox; every snippet is a step that can
            # start failing after one. Not a defect - a number to keep low.
            n_code = 0
            for s in steps:
                if "1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8" in str(s.get("stepType", "")):
                    n_code = n_code + 1
            if n_code:
                infos.append("%s: %d code-snippet step(s) - prefer native steps / Jinja where they "
                             "can do the job (conventions.md, 'Native step or Code Snippet?')" % (name, n_code))

            ok("%s: %d steps, %d routes" % (name, len(steps), len(routes)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: validate_playbook.py <playbook.json>")
        sys.exit(2)
    try:
        main(sys.argv[1])
    except Exception as e:
        err("could not parse: %s" % e)

    if JINJA_ENV is None:
        infos.append("jinja2 is not installed, so templates were not syntax-checked "
                     "(add the optional jinja2 Python package to enable)")
    for m in oks:
        print("  ok    %s" % m)
    for m in infos:
        print("  INFO  %s" % m)
    for m in warns:
        print("  WARN  %s" % m)
    for m in errors:
        print("  ERROR %s" % m)
    print("\n%d error(s), %d warning(s)" % (len(errors), len(warns)))
    sys.exit(1 if errors else 0)
