#!/usr/bin/env python3
"""
Harvest connector configurations from a reference playbook export.

    python3 scripts/extract_connector_configs.py <reference.json> [more.json ...]

Config uuids, connector versions and picklist uuids are specific to one
FortiSOAR instance. They cannot be guessed, and a playbook shipped without them
imports but cannot run. Rather than hardcoding values that would be wrong for
every other instance, ask the user once for a playbook export containing the
connector steps they use, and run this against it.

Output is a table to paste into the build, plus a JSON block for reuse.
"""
import json
import sys
import re


def walk(path):
    doc = json.load(open(path, encoding="utf-8"))
    found = {}
    picklists = {}
    subplays = {}
    for coll in (doc.get("data") or []):
        for wf in (coll.get("workflows") or []):
            for st in (wf.get("steps") or []):
                a = st.get("arguments") or {}
                conn = a.get("connector")
                if conn:
                    cfg = str(a.get("config") or "")
                    ver = str(a.get("version") or "")
                    if cfg and not cfg.startswith("<"):
                        key = conn
                        if key not in found:
                            found[key] = {"connector": conn, "config": cfg,
                                          "version": ver, "display": a.get("name") or "",
                                          "operations": [], "seen_in": []}
                        op = a.get("operation")
                        if op and op not in found[key]["operations"]:
                            found[key]["operations"].append(op)
                        src = "%s / %s" % (wf.get("name", "?"), st.get("name", "?"))
                        if len(found[key]["seen_in"]) < 3:
                            found[key]["seen_in"].append(src)
                        # a second, different config for the same connector is
                        # worth surfacing - some instances have several
                        if found[key]["config"] != cfg:
                            alt = conn + " (alt)"
                            found[alt] = {"connector": conn, "config": cfg,
                                          "version": ver, "display": a.get("name") or "",
                                          "operations": [op] if op else [],
                                          "seen_in": [src]}

                # picklist uuids appear in create/update record steps
                blob = json.dumps(a)
                for m in re.finditer(r'/api/3/picklists/([0-9a-f\-]{36})', blob):
                    picklists[m.group(1)] = picklists.get(m.group(1), 0) + 1
                ref = a.get("workflowReference")
                if ref:
                    subplays[str(ref)] = st.get("name", "?")
    return found, picklists, subplays


def main(paths):
    allc = {}
    allp = {}
    alls = {}
    for p in paths:
        try:
            f, pk, sp = walk(p)
        except Exception as e:
            print("could not read %s: %s" % (p, e))
            continue
        for k, v in f.items():
            if k not in allc:
                allc[k] = v
            else:
                for o in v["operations"]:
                    if o not in allc[k]["operations"]:
                        allc[k]["operations"].append(o)
        for k, v in pk.items():
            allp[k] = allp.get(k, 0) + v
        alls.update(sp)

    if not allc:
        print("No connector steps with a real config found.")
        print("Ask the user for an export that contains the connector steps they use.")
        return

    print("CONNECTOR CONFIGURATIONS FOUND")
    print("=" * 78)
    for k in sorted(allc):
        v = allc[k]
        print("\n  connector : %s" % v["connector"])
        print("  display   : %s" % v["display"])
        print("  config    : %s" % v["config"])
        print("  version   : %s" % (v["version"] or "(not set)"))
        if v["operations"]:
            print("  operations: %s" % ", ".join(v["operations"]))
        print("  seen in   : %s" % "; ".join(v["seen_in"]))

    print("\n\nREUSE BLOCK")
    print("=" * 78)
    out = {}
    for k in sorted(allc):
        out[allc[k]["connector"]] = {"config": allc[k]["config"],
                                     "version": allc[k]["version"]}
    print(json.dumps(out, indent=2))

    if allp:
        print("\n\nPICKLIST UUIDS SEEN (verify meaning before reusing)")
        print("=" * 78)
        for k in sorted(allp, key=lambda x: -allp[x]):
            print("  %s  (used %d time(s))" % (k, allp[k]))

    if alls:
        print("\n\nSUB-PLAYBOOK REFERENCES")
        print("=" * 78)
        for k, v in alls.items():
            print("  %s  <- step '%s'" % (k, v))

    print("\n\nUSE THESE VALUES DIRECTLY in the generated playbook's connector steps.")
    print("If a connector the new playbook needs is NOT listed above, ask the user")
    print("for it specifically rather than shipping a placeholder.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: extract_connector_configs.py <reference.json> [more.json ...]")
        sys.exit(2)
    main(sys.argv[1:])
