#!/usr/bin/env python3
"""Live end-to-end check against a real MISP instance (opt-in; needs network + credentials).

    MISP_URL=https://localhost:8443 MISP_KEY=<api key> [MISP_VERIFY_TLS=0] python tools/tests/e2e_misp.py

For every hunt in hunts/: hunt.md → MISP event JSON → POST /events/add (or /events/edit
if it already exists) → GET it back as MISP serialises it → huntmd import → must be
byte-exact with the source. Also checks the instance has the hunt-ex taxonomy and the
threat-hunt-* templates at the pinned versions, that objects/attributes/references/tags
all survive, that a run result lands as a threat-hunt-finding, that the objects-only
(attachment-stripped) re-import is a clean draft, and — the point of HUNT-EX — that
restSearch by hunt-ex tags finds the hunts.

Developed against MISP 2.5.44 via misp-docker (see PROFILES.md §3 for the operational
notes this surfaced). Not part of check.py: it needs a running MISP.
"""
import base64  # noqa: F401
import json
import os
import pathlib
import ssl
import subprocess  # noqa: F401
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from huntmd.misp import markdown_to_misp, misp_to_markdown, misp_to_playbook, is_misp_event
from huntmd.core import parse_markdown, validate_markdown
import yaml

BASE = os.environ.get("MISP_URL", "").rstrip("/")
KEY = os.environ.get("MISP_KEY", "")
if not BASE or not KEY:
    sys.exit("set MISP_URL and MISP_KEY (see docstring)")
ctx = ssl.create_default_context()
if os.environ.get("MISP_VERIFY_TLS", "0") == "0":
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": KEY, "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

fails = []
def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else ': ' + str(detail)[:400]}")
    if not ok: fails.append(name)

# --- 0. instance knows the vocab -------------------------------------------------
st, tax = api("GET", "/taxonomies/index")
hx = [t for t in tax if t.get("Taxonomy", {}).get("namespace") == "hunt-ex"]
check("instance has hunt-ex taxonomy", bool(hx), f"http {st}, {len(tax)} taxonomies")
if hx and not hx[0]["Taxonomy"].get("enabled"):
    tid = hx[0]["Taxonomy"]["id"]
    print("   enabling hunt-ex taxonomy…", api("POST", f"/taxonomies/enable/{tid}")[0], api("POST", f"/taxonomies/addTag/{tid}")[0])
st, tmpls = api("GET", "/objectTemplates/index")
names = {t["ObjectTemplate"]["name"]: t["ObjectTemplate"] for t in tmpls}
for n in ("threat-hunt-context", "threat-hunt-hypothesis", "threat-hunt-query", "threat-hunt-finding"):
    check(f"object template {n} present", n in names, f"http {st}, {len(tmpls)} templates")
    if n in names:
        from huntmd.misp import _TEMPLATES
        check(f"  template uuid/version match pinned ({_TEMPLATES[n][1]})", names[n]["uuid"] == _TEMPLATES[n][0] and str(names[n]["version"]) == _TEMPLATES[n][1], f"instance has {names[n]['uuid']} v{names[n]['version']}")

# --- 1. push each hunt -------------------------------------------------------------
# Every hunt in hunts/; the kerberoasting run result rides along as a finding.
cases = [(p.name, (ROOT / "examples/results/kerberoasting-run.yaml") if p.name == "kerberoasting.md" else None) for p in sorted((ROOT / "hunts").glob("*.md"))]
for name, result_path in cases:
    print(f"\n{name}")
    md = (ROOT / "hunts" / name).read_text()
    result = yaml.safe_load(result_path.read_text()) if result_path else None
    ev = markdown_to_misp(md, result=result)
    # A deleted event's uuid is blocklisted (and our ids are deterministic) — clear it, then add-or-edit.
    st, bl = api("GET", "/eventBlocklists/index")
    for b in bl if isinstance(bl, list) else []:
        b = b.get("EventBlocklist", b)
        if b.get("event_uuid") == ev["Event"]["uuid"]:
            api("POST", f"/eventBlocklists/delete/{b['id']}")
    st, existing = api("GET", "/events/view/" + ev["Event"]["uuid"])
    if st == 200 and "Event" in existing:
        st, resp = api("POST", "/events/edit/" + ev["Event"]["uuid"], ev)
        check("POST /events/edit (update in place) accepted", st == 200 and "Event" in resp, f"http {st}: {json.dumps(resp)[:400]}")
    else:
        st, resp = api("POST", "/events/add", ev)
        check("POST /events/add accepted", st == 200 and "Event" in resp, f"http {st}: {json.dumps(resp)[:400]}")
    if not (st == 200 and "Event" in resp):
        continue
    eid = resp["Event"]["id"]
    sent_objs = ev["Event"]["Object"]; got_objs = resp["Event"].get("Object", [])
    check("all objects stored", len(got_objs) == len(sent_objs), f"sent {len(sent_objs)} got {len(got_objs)}")
    sent_attr = sum(len(o["Attribute"]) for o in sent_objs); got_attr = sum(len(o.get("Attribute", [])) for o in got_objs)
    check("all object attributes stored", got_attr == sent_attr, f"sent {sent_attr} got {got_attr}")
    sent_refs = sum(len(o["ObjectReference"]) for o in sent_objs); got_refs = sum(len(o.get("ObjectReference", [])) for o in got_objs)
    check("all object references stored", got_refs == sent_refs, f"sent {sent_refs} got {got_refs}")
    sent_tags = {t["name"] for t in ev["Event"]["Tag"]}; got_tags = {t["name"] for t in resp["Event"].get("Tag", [])}
    check("all event tags stored", sent_tags <= got_tags, f"missing {sent_tags - got_tags}")
    got_top = resp["Event"].get("Attribute", [])
    check("attachment + link attributes stored", len(got_top) == len(ev["Event"]["Attribute"]), f"sent {len(ev['Event']['Attribute'])} got {[a['type'] for a in got_top]}")

    # --- 2. fetch back as MISP serialises it, re-import ------------------------------
    st, fetched = api("GET", f"/events/view/{eid}")
    check("GET /events/view", st == 200 and "Event" in fetched, st)
    # attachments: /events/view doesn't inline data; ask for it
    st, fetched_data = api("POST", "/events/restSearch", {"eventid": eid, "includeAttachments": 1, "returnFormat": "json"})
    resp_ev = (fetched_data.get("response") or [{}])[0]
    check("restSearch returns the event with attachment data", any(a.get("type") == "attachment" and a.get("data") for a in resp_ev.get("Event", {}).get("Attribute", [])), json.dumps(fetched_data)[:300])
    check("re-fetched event is detected as MISP by huntmd", is_misp_event(fetched_data), "")
    back = misp_to_markdown(fetched_data)
    check("MISP → hunt.md is byte-exact with the source", back == md, "diff: " + next((f"{i}: {a!r} vs {b!r}" for i, (a, b) in enumerate(zip(back.splitlines(), md.splitlines())) if a != b), "length differs"))
    # objects-only path through MISP's serialisation
    stripped = json.loads(json.dumps(fetched))
    stripped["Event"]["Attribute"] = [a for a in stripped["Event"].get("Attribute", []) if a["type"] != "attachment"]
    draft = misp_to_markdown(stripped)
    dpb = parse_markdown(draft)
    errs = [str(i) for i in validate_markdown(draft, profile="format") if i.level == "error"]
    nq = sum(1 for s in parse_markdown(md).steps if s.kind == "query")
    check("objects-only re-import from MISP → clean draft, queries preserved", not errs and sum(1 for s in dpb.steps if s.kind == "query") == nq, "; ".join(errs[:2]) or f"queries {sum(1 for s in dpb.steps if s.kind=='query')} != {nq}")
    if result:
        f = [o for o in fetched["Event"]["Object"] if o["name"] == "threat-hunt-finding"]
        check("finding object stored with outcome/conclusion", bool(f) and {a["object_relation"] for a in f[0]["Attribute"]} >= {"outcome", "conclusion"}, [o["name"] for o in fetched["Event"]["Object"]])
        check("finding relationship 'concludes' kept", bool(f) and any(r["relationship_type"] == "concludes" for r in f[0].get("ObjectReference", [])), f and f[0].get("ObjectReference"))
        # 0.6: recorded outcome / handoff / period (SPEC §12.3) survive as tags + context datetimes
        check("hunt-ex:handoff from the run result stored", 'hunt-ex:handoff="keep-as-periodic-hunt"' in got_tags, sorted(got_tags))
        ctx_obj = next((o for o in fetched["Event"]["Object"] if o["name"] == "threat-hunt-context"), {})
        check("period-start/period-end stored on the context object (datetime)", {a["object_relation"] for a in ctx_obj.get("Attribute", [])} >= {"period-start", "period-end"}, sorted(a["object_relation"] for a in ctx_obj.get("Attribute", [])))
    # 0.6: the neutral hunt: block classifies without a misp: block; provenance/narrative land on the objects
    src_pb = parse_markdown(md)
    hb = src_pb.meta.get("hunt") or {}
    for pred in ("trigger", "applicability", "handoff"):
        if hb.get(pred):
            check(f"hunt.{pred} → hunt-ex:{pred} tag stored", f'hunt-ex:{pred}="{hb[pred]}"' in got_tags, sorted(t for t in got_tags if t.startswith("hunt-ex:")))
    hyp_obj = next((o for o in fetched["Event"]["Object"] if o["name"] == "threat-hunt-hypothesis"), {})
    hyp_rel = {a["object_relation"]: a["value"] for a in hyp_obj.get("Attribute", [])}
    if src_pb.meta.get("analysis"):
        check("analysis: stored verbatim on the hypothesis object", hyp_rel.get("analysis", "").strip() == str(src_pb.meta["analysis"]).strip(), hyp_rel.get("analysis", "")[:120])
    if src_pb.meta.get("rationale"):
        check("rationale: stored on the hypothesis object", "rationale" in hyp_rel, sorted(hyp_rel))
    prov = src_pb.meta.get("provenance") or {}
    if prov.get("authors"):
        ctx_obj = next((o for o in fetched["Event"]["Object"] if o["name"] == "threat-hunt-context"), {})
        check("provenance.authors stored as contributor", any(a["object_relation"] == "contributor" for a in ctx_obj.get("Attribute", [])), sorted(a["object_relation"] for a in ctx_obj.get("Attribute", [])))
    # the draft re-import writes hunt: and target telemetry (0.6), not a misp: classification
    check("objects-only draft carries hunt: classification from the tags", bool(dpb.meta.get("hunt")) and "trigger" in dpb.meta["hunt"], dpb.meta.get("hunt"))
    check("objects-only draft puts telemetry planes on the targets", any(t.get("telemetry") for t in dpb.meta.get("targets", {}).values()), dpb.meta.get("targets"))
    check("objects-only draft records provenance.source = misp event uuid", (dpb.meta.get("provenance") or {}).get("source", {}).get("ref") == ev["Event"]["uuid"], dpb.meta.get("provenance"))

# --- 3. the whole point: peers can filter --------------------------------------------
print("\nsearch")
st, found = api("POST", "/events/restSearch", {"tags": ['hunt-ex:telemetry="identity"', 'hunt-ex:query-language="kusto"'], "returnFormat": "json"})
infos = [e["Event"]["info"] for e in found.get("response", [])]
check('restSearch tags identity ∧ kusto finds all three hunts', {"Kerberoasting hunt", "Scattered Spider identity-takeover hunt", "ADCS ESC1 certificate-template abuse hunt"} <= set(infos), f"http {st}: {infos}")
st, found = api("POST", "/events/restSearch", {"tags": ['hunt-ex:trigger="sector-alert"'], "returnFormat": "json"})
infos = [e["Event"]["info"] for e in found.get("response", [])]
check("restSearch by hunt-ex:trigger (from the neutral hunt: block) finds the Scattered Spider hunt only", infos == ["Scattered Spider identity-takeover hunt"], infos)
st, found = api("POST", "/events/restSearch", {"tags": ['hunt-ex:handoff="promote-to-detection"'], "returnFormat": "json"})
infos = sorted(e["Event"]["info"] for e in found.get("response", []))
check("restSearch by hunt-ex:handoff finds the two promote-to-detection hunts", infos == ["ADCS ESC1 certificate-template abuse hunt", "Scattered Spider identity-takeover hunt"], infos)
st, found = api("POST", "/events/restSearch", {"tags": ['hunt-ex:outcome="inconclusive"'], "returnFormat": "json"})
infos = [e["Event"]["info"] for e in found.get("response", [])]
check("restSearch by outcome finds only the hunt with a finding", infos == ["Kerberoasting hunt"], infos)
st, found = api("POST", "/attributes/restSearch", {"object_relation": "attack-id", "value": "T1558.003", "returnFormat": "json"})
check("attribute search by attack-id T1558.003", any(a.get("value") == "T1558.003" for a in found.get("response", {}).get("Attribute", [])), json.dumps(found)[:200])

print()
print("FAILED: " + ", ".join(fails) if fails else "All end-to-end checks passed.")
sys.exit(1 if fails else 0)
