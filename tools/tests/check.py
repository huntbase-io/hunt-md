#!/usr/bin/env python3
"""Regression checks for the hunt.md reference tooling.

Plain stdlib — no pytest, no network. Run from anywhere:

    python tools/tests/check.py

Checks, in order of what tends to break:

1. Every hunt in `hunts/` parses, lints clean, and converts to all targets.
2. `md -> CACAO -> md` is **exact** for every hunt: step kinds, slugs, targets,
   parameters and every edge survive. This is the claim PROFILES.md §2 makes, so
   it is enforced rather than trusted.
3. Every reference conversion in `examples/cacao-import/` still parses and lints.
4. The publication guardrail works: `--max-tlp green` rejects an amber hunt.
5. `md -> MISP -> md` is **exact** (the source rides along as an attachment), the
   HUNT-EX objects/tags are present, a run result becomes a finding, and an
   objects-only event (no attachment) still imports as a lint-clean draft.

Exits non-zero on the first failing group, printing what differed.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from huntmd.cacao import cacao_to_markdown, markdown_to_cacao  # noqa: E402
from huntmd.misp import is_misp_event, markdown_to_misp, misp_to_markdown  # noqa: E402
from huntmd.core import (  # noqa: E402
    definition_to_markdown,
    markdown_to_definition,
    parse_markdown,
    validate_markdown,
)

failures: list[str] = []


def report(group: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {group}{'' if ok else ': ' + detail}")
    if not ok:
        failures.append(group)


def fingerprint(md: str) -> dict:
    """The semantic content a round-trip must preserve."""
    pb = parse_markdown(md)
    return {
        "kinds": Counter(s.kind for s in pb.steps),
        "steps": {s.slug: (s.target, s.lang) for s in pb.steps},
        "targets": sorted(pb.meta.get("targets") or {}),
        "parameters": pb.meta.get("parameters"),
        "edges": sorted((e.frm, e.to, e.branch) for e in pb.edges),
    }


print("hunts/ — parse, lint, convert")
hunts = sorted((ROOT / "hunts").glob("*.md"))
if not hunts:
    report("hunts present", False, "no hunts found")
for path in hunts:
    md = path.read_text(encoding="utf-8")
    errors = [str(i) for i in validate_markdown(md, profile="format") if i.level == "error"]
    report(f"{path.name} lints (format)", not errors, "; ".join(errors[:2]))
    try:
        markdown_to_definition(md)
        markdown_to_cacao(md)
        ok, detail = True, ""
    except Exception as exc:  # noqa: BLE001 - surface any conversion failure
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    report(f"{path.name} converts (definition + cacao)", ok, detail)

print("\nround-trip — md -> CACAO -> md must be exact")
for path in hunts:
    md = path.read_text(encoding="utf-8")
    try:
        before, after = fingerprint(md), fingerprint(cacao_to_markdown(markdown_to_cacao(md)))
    except Exception as exc:  # noqa: BLE001
        report(f"{path.name} round-trip", False, f"{type(exc).__name__}: {exc}")
        continue
    drift = [k for k in before if before[k] != after[k]]
    detail = ""
    if drift:
        key = drift[0]
        detail = f"{key} changed: {before[key]!r} -> {after[key]!r}"[:300]
    report(f"{path.name} round-trip", not drift, detail)

print("\nround-trip — md -> definition -> md (the path Huntbase vendors)")
_VALID_NODE_TYPES = {"query", "collection", "action", "checkpoint", "task", "analytic"}
for path in hunts:
    md = path.read_text(encoding="utf-8")
    try:
        defn = markdown_to_definition(md)
    except Exception as exc:  # noqa: BLE001
        report(f"{path.name} definition round-trip", False, f"{type(exc).__name__}: {exc}")
        continue
    # Shape: valid node types, parents reference existing nodes, no duplicate parents.
    node_ids = {n.get("id") for n in defn["nodes"]}
    shape_errs: list[str] = []
    for n in defn["nodes"]:
        if n.get("type") not in _VALID_NODE_TYPES:
            shape_errs.append(f"{n.get('id')}: bad type {n.get('type')!r}")
        pars = n.get("parents") or []
        if len(pars) != len({(p.get("id"), p.get("branch"), p.get("kind")) for p in pars}):
            shape_errs.append(f"{n.get('id')}: duplicate parents {pars!r}")
        for p in pars:
            if p.get("id") not in node_ids:
                shape_errs.append(f"{n.get('id')}: parent {p.get('id')!r} missing")
    report(f"{path.name} definition shape", not shape_errs, "; ".join(shape_errs[:2]))
    # Fingerprint survives md -> definition -> md.
    try:
        before, after = fingerprint(md), fingerprint(definition_to_markdown(defn))
    except Exception as exc:  # noqa: BLE001
        report(f"{path.name} definition round-trip", False, f"{type(exc).__name__}: {exc}")
        continue
    # target/lang are best-effort on the definition inverse; the node graph
    # (node kinds + edges incl. branch) must survive exactly. Parallel/group
    # pseudo-steps aren't nodes and aren't regenerated (documented sugar loss),
    # so compare only the six real node kinds.
    _node_kinds = {"query", "collection", "agent", "decision", "task", "action"}
    before_k = Counter({k: v for k, v in before["kinds"].items() if k in _node_kinds})
    after_k = Counter({k: v for k, v in after["kinds"].items() if k in _node_kinds})
    drift = []
    if before_k != after_k:
        drift.append("kinds")
    if before["edges"] != after["edges"]:
        drift.append("edges")
    detail = ""
    if drift:
        key = drift[0]
        detail = f"{key} changed: {before[key]!r} -> {after[key]!r}"[:300]
    report(f"{path.name} definition round-trip", not drift, detail)

print("\nsession-derived export — UUID ids must render as readable slugs")
# A Huntbase session-derived definition carries DB UUIDs as node ids (not
# authored slugs). The export must key headings + transitions off the label so
# the document is legible and re-importable — regression for the UUID-heading bug.
_U = [
    "4d63af23-8d2e-429a-81b6-52ce5a1fd9a5",
    "76a64083-16a5-4517-a07f-aa34e1859ace",
    "7db3ca3a-d23e-4140-97f0-51fbc2b85522",
]
_derived_defn = {
    "hunt": {"name": "Derived from session"},
    "nodes": [
        {"id": _U[0], "type": "query", "label": "Identify Keycloak Registrations",
         "primitive_config": {"content": "SELECT 1", "dsl": "spl", "target": "siem"}},
        {"id": _U[1], "type": "query", "label": "Detect Spoofed Attestation",
         "primitive_config": {"content": "SELECT 2", "dsl": "spl", "target": "siem"},
         "parents": [{"id": _U[0]}]},
        {"id": _U[2], "type": "task", "label": "Consolidate Findings",
         "config": {}, "parents": [{"id": _U[1]}]},
    ],
}
_md = definition_to_markdown(_derived_defn)
_headings = [ln[3:].strip() for ln in _md.splitlines() if ln.startswith("## ")]
report(
    "no UUID headings (slugs derived from labels)",
    bool(_headings) and not any(h in _U for h in _headings),
    f"headings={_headings}",
)
report(
    "readable slug present",
    "identify-keycloak-registrations" in _headings,
    f"headings={_headings}",
)
_reparsed = parse_markdown(_md)
report(
    "edges survive UUID→slug export",
    sorted((e.frm, e.to) for e in _reparsed.edges)
    == [("detect-spoofed-attestation", "consolidate-findings"),
        ("identify-keycloak-registrations", "detect-spoofed-attestation")],
    f"edges={sorted((e.frm, e.to) for e in _reparsed.edges)}",
)
report(
    "unset DSL is not fabricated as sqlite",
    "```sqlite" not in _md and "```spl" in _md,
)

print("\nexamples/cacao-import/ — reference conversions still valid")
examples = sorted(p for p in (ROOT / "examples" / "cacao-import").glob("*.md") if p.name != "README.md")
for path in examples:
    md = path.read_text(encoding="utf-8")
    errors = [str(i) for i in validate_markdown(md, profile="format") if i.level == "error"]
    report(f"{path.name}", not errors, "; ".join(errors[:2]))
if not examples:
    report("examples present", False, "no reference conversions found")

print("\npublication guardrail — --max-tlp")
amber = "---\ntlp: amber\nhypothesis: x\n---\n\n# t\n\n## s\n```manual target=a\ndo\n```\n"
green = amber.replace("tlp: amber", "tlp: green")
unmarked = amber.replace("tlp: amber\n", "")
report(
    "amber hunt rejected at --max-tlp green",
    any(i.level == "error" and "exceeds" in i.message for i in validate_markdown(amber, profile="format", max_tlp="green")),
)
report(
    "green hunt accepted at --max-tlp green",
    not any("tlp" in i.message for i in validate_markdown(green, profile="format", max_tlp="green")),
)
report(
    "unmarked hunt rejected (absence is not consent)",
    any(i.level == "error" and "no 'tlp:'" in i.message for i in validate_markdown(unmarked, profile="format", max_tlp="green")),
)

print("\nguardrails (SPEC §8.1)")
base = "---\ntlp: green\nhypothesis: x\n{extra}---\n\n# t\n\n## look\n```agent target=a\nobjective: o\ntools: [a]\nmax_iterations: 2\n```\n"
from huntmd.core import effective_guardrails  # noqa: E402

report(
    "defaults apply when no block is declared",
    effective_guardrails({}) == {
        "telemetry": "untrusted",
        "evidence": "citation_required",
        "missing_data": "not_benign",
        "claims": "no_unsupported",
    },
)
relaxed = validate_markdown(base.format(extra="guardrails: { telemetry: trusted }\n"), profile="format")
report(
    "relaxing a guardrail warns",
    any(i.level == "warn" and "relaxed" in i.message for i in relaxed),
)
bad_key = validate_markdown(base.format(extra="guardrails: { telemetryy: trusted }\n"), profile="format")
report("unknown guardrail key is an error", any(i.level == "error" and "unknown guardrail" in i.message for i in bad_key))
bad_val = validate_markdown(base.format(extra="guardrails: { telemetry: whatever }\n"), profile="format")
report("invalid guardrail value is an error", any(i.level == "error" and "not in" in i.message for i in bad_val))
report(
    "guardrails reach the runtime definition",
    markdown_to_definition(base.format(extra=""))["hunt"]["meta"].get("guardrails", {}).get("telemetry") == "untrusted",
)
report(
    "guardrails travel with the CACAO export",
    markdown_to_cacao(base.format(extra=""))["x_hunt"]["guardrails"]["telemetry"] == "untrusted",
)

print("\nconfidence + unavailable (SPEC §7.2)")
fuzzy = (
    "---\ntlp: green\nhypothesis: x\n---\n\n# t\n\n## judge\n"
    'if~: "looks bad" (confidence: {conf}, judge=a)\n'
    "then: → act\nindeterminate: → review\n{unavail}else: → close\n\n"
    "## act\n```manual target=a\nx\n```\n\n## review\n```manual target=a\nx\n```\n\n## close\n```manual target=a\nx\n```\n"
)
pb_ordinal = parse_markdown(fuzzy.format(conf="high", unavail=""))
report("ordinal confidence parses", pb_ordinal.steps[0].confidence == "high")
report("judge parses alongside it", pb_ordinal.steps[0].judge == "a")
numeric_md = fuzzy.format(conf="high", unavail="").replace("confidence: high", "confidence >= 0.9")
report(
    "numeric confidence warns (not calibrated)",
    any(i.level == "warn" and "not calibrated" in i.message for i in validate_markdown(numeric_md, profile="format")),
)
report(
    "invalid ordinal is an error",
    any(i.level == "error" for i in validate_markdown(fuzzy.format(conf="very-high", unavail=""), profile="format")),
)
with_unavail = fuzzy.format(conf="high", unavail="unavailable: → review\n")
report(
    "unavailable: routes to a real step",
    any(e.branch == "on_unavailable" for e in parse_markdown(with_unavail).edges),
)
report(
    "unavailable: → end is rejected under missing_data: not_benign",
    any(
        i.level == "error" and "never examined" in i.message
        for i in validate_markdown(fuzzy.format(conf="high", unavail="unavailable: → end\n"), profile="format")
    ),
)
report(
    "unavailable: survives md -> CACAO -> md",
    any(e.branch == "on_unavailable" for e in parse_markdown(cacao_to_markdown(markdown_to_cacao(with_unavail))).edges),
)

print("\nMISP / HUNT-EX — export, exact round-trip, finding, draft import")
import base64  # noqa: E402
import json  # noqa: E402
import yaml  # noqa: E402

for path in hunts:
    md = path.read_text(encoding="utf-8")
    try:
        ev = markdown_to_misp(md)
        event = ev["Event"]
        json.dumps(ev)  # must be serialisable as-is
        names = [o["name"] for o in event["Object"]]
        tags = {t["name"] for t in event["Tag"]}
        n_queries = sum(1 for s in parse_markdown(md).steps if s.kind == "query")
        shape_ok = (
            names.count("threat-hunt-context") == 1
            and names.count("threat-hunt-hypothesis") == 1
            and names.count("threat-hunt-query") == n_queries
            and 'hunt-ex:content="hypothesis"' in tags
            and 'hunt-ex:content="query"' in tags
            and any(t.startswith('hunt-ex:query-language="') for t in tags)
            and any(t.startswith("tlp:") for t in tags)
            and all(o["template_uuid"] and o["template_version"] for o in event["Object"])
            and all(any(r["relationship_type"] == "tests" for r in o["ObjectReference"]) for o in event["Object"] if o["name"] == "threat-hunt-query")
        )
        report(f"{path.name} → MISP event shape (objects + hunt-ex tags)", shape_ok, f"objects={names} tags={sorted(tags)}"[:300])
        # Attack ids land on the hypothesis object.
        hyp = next(o for o in event["Object"] if o["name"] == "threat-hunt-hypothesis")
        got = sorted(a["value"] for a in hyp["Attribute"] if a["object_relation"] == "attack-id")
        want = sorted(str(l).split(".", 1)[1].upper() for l in parse_markdown(md).meta.get("labels", []) if str(l).startswith("attack."))
        report(f"{path.name} ATT&CK ids on hypothesis", got == want, f"{got} != {want}")
        # Exact round-trip via the attachment.
        report(f"{path.name} md → MISP → md is byte-exact", misp_to_markdown(json.loads(json.dumps(ev))) == md)
        # Deterministic ids.
        report(f"{path.name} MISP export is deterministic", json.dumps(markdown_to_misp(md), sort_keys=True) == json.dumps(ev, sort_keys=True))
        # Objects-only (someone else's MISP instance stripped the attachment): still a lint-clean draft.
        stripped = json.loads(json.dumps(ev))
        stripped["Event"]["Attribute"] = [a for a in stripped["Event"]["Attribute"] if a["type"] != "attachment"]
        report(f"{path.name} objects-only event is detected as MISP", is_misp_event(stripped))
        draft = misp_to_markdown(stripped)
        dpb = parse_markdown(draft)
        derr = [str(i) for i in validate_markdown(draft, profile="format") if i.level == "error"]
        report(
            f"{path.name} objects-only import → draft lints clean, keeps queries + hypothesis",
            not derr and sum(1 for s in dpb.steps if s.kind == "query") == n_queries and str(dpb.meta.get("hypothesis")).strip() == str(parse_markdown(md).meta.get("hypothesis")).strip() and "TODO" in draft,
            "; ".join(derr[:2]) or "content drift",
        )
    except Exception as exc:  # noqa: BLE001
        report(f"{path.name} MISP export", False, f"{type(exc).__name__}: {exc}")

# A run result becomes a threat-hunt-finding + outcome tags.
_kb = (ROOT / "hunts" / "kerberoasting.md").read_text(encoding="utf-8")
_run = yaml.safe_load((ROOT / "examples" / "results" / "kerberoasting-run.yaml").read_text(encoding="utf-8"))
_ev = markdown_to_misp(_kb, result=_run)["Event"]
_finding = [o for o in _ev["Object"] if o["name"] == "threat-hunt-finding"]
_ftags = {t["name"] for t in _ev["Tag"]}
report(
    "run result → threat-hunt-finding + hunt-ex:outcome/byproduct tags",
    len(_finding) == 1
    and any(r["relationship_type"] == "concludes" for r in _finding[0]["ObjectReference"])
    and 'hunt-ex:content="finding"' in _ftags
    and 'hunt-ex:outcome="inconclusive"' in _ftags  # suspicious ≠ confirmed
    and 'hunt-ex:byproduct="data-source-gap"' in _ftags,  # edr was never examined
    f"finding={len(_finding)} tags={sorted(_ftags)}"[:300],
)
_benign_run = {"hunt_result": {"hunt": "k", "run": "r", "disposition": "benign", "confidence": "high", "evidence_summary": {"benign_supporting": ["rotation job"]}}}
_bt = {t["name"] for t in markdown_to_misp(_kb, result=_benign_run)["Event"]["Tag"]}
report("benign-with-evidence → hypothesis-confirmed-benign", 'hunt-ex:outcome="hypothesis-confirmed-benign"' in _bt, str(sorted(_bt)))
_mal = {t["name"] for t in markdown_to_misp(_kb, result={"hunt_result": {"hunt": "k", "run": "r", "disposition": "malicious"}})["Event"]["Tag"]}
report("malicious → hypothesis-confirmed-malicious", 'hunt-ex:outcome="hypothesis-confirmed-malicious"' in _mal)
# The misp: frontmatter block is linted against the taxonomy.
_badmisp = "---\nhypothesis: x\ntlp: green\nlabels: [attack.t1000]\nmisp: {trigger: vibes, telemetry: [identity]}\n---\n# t\n## q\n```kql target=s\nx\n```\n→ end\n"
report("misp: block off-vocabulary value warns under --profile misp", any("vibes" in str(i) for i in validate_markdown(_badmisp, profile="misp")))
report("--profile format ignores the misp: block", not any("vibes" in str(i) for i in validate_markdown(_badmisp, profile="format")))
# A hand-authored MISP event (no hunt.md provenance at all) imports as a draft.
_foreign = {
    "Event": {
        "info": "Peer hunt: OAuth consent phishing",
        "uuid": "11111111-2222-3333-4444-555555555555",
        "threat_level_id": "2",
        "Tag": [{"name": "tlp:amber"}, {"name": 'hunt-ex:telemetry="saas"'}, {"name": 'hunt-ex:trigger="sector-alert"'}],
        "Attribute": [],
        "Object": [
            {"name": "threat-hunt-context", "Attribute": [{"object_relation": "hunt-title", "value": "OAuth consent phishing"}, {"object_relation": "purpose", "value": "ISAC alert"}]},
            {"name": "threat-hunt-hypothesis", "Attribute": [{"object_relation": "hypothesis-id", "value": "H1"}, {"object_relation": "hypothesis", "value": "Users granted consent to a malicious app"}, {"object_relation": "attack-id", "value": "T1528"}]},
            {"name": "threat-hunt-query", "Attribute": [{"object_relation": "query", "value": "AuditLogs | where OperationName == 'Consent to application'"}, {"object_relation": "query-language", "value": "KQL"}, {"object_relation": "data-source", "value": "AuditLogs"}]},
            {"name": "sigma", "Attribute": [{"object_relation": "sigma", "value": "title: x\nlogsource: {product: azure}\ndetection: {sel: {OperationName: Consent to application}, condition: sel}"}, {"object_relation": "sigma-rule-name", "value": "consent-grant"}]},
            {"name": "threat-hunt-finding", "Attribute": [{"object_relation": "outcome", "value": "True Positive"}, {"object_relation": "conclusion", "value": "Two grants to an unverified publisher."}]},
        ],
    }
}
_fmd = misp_to_markdown(_foreign)
_fpb = parse_markdown(_fmd)
_ferr = [str(i) for i in validate_markdown(_fmd, profile="format") if i.level == "error"]
report(
    "foreign MISP event → draft: kql + sigma queries, ATT&CK label, tlp, finding as review task, misp: provenance",
    not _ferr
    and sorted(s.lang for s in _fpb.steps if s.kind == "query") == ["kql", "sigma"]
    and "attack.t1528" in _fpb.meta["labels"]
    and _fpb.meta["tlp"] == "amber"
    and any(s.kind == "task" for s in _fpb.steps)
    and _fpb.meta["misp"]["telemetry"] == "saas"
    and _fpb.meta["misp"]["trigger"] == "sector-alert",
    "; ".join(_ferr[:2]) or _fmd[:300],
)
for fx in sorted((ROOT / "examples" / "misp-export").glob("*.json")):
    fev = json.loads(fx.read_text(encoding="utf-8"))
    fmd = misp_to_markdown(fev)
    ferr = [str(i) for i in validate_markdown(fmd, profile="format") if i.level == "error"]
    report(f"examples/misp-export/{fx.name} imports + lints", is_misp_event(fev) and not ferr, "; ".join(ferr[:2]))
report("attachment round-trip decodes utf-8", base64.b64decode(next(a["data"] for a in _ev["Attribute"] if a["type"] == "attachment")).decode() == _kb)

print("\nrun results (SPEC §12)")
from huntmd.results import validate_result  # noqa: E402

good = {
    "hunt_result": {
        "hunt": "k",
        "run": "r1",
        "disposition": "benign",
        "confidence": "high",
        "evidence_summary": {"benign_supporting": ["scheduled rotation job explains the bursts"]},
        "step_results": [
            {"step": "triage", "answer_status": "matched", "assessment": "benign", "explanation": "e", "evidence": [{"step": "q"}]}
        ],
    }
}
report("a well-formed result passes", not [i for i in validate_result(good) if i.level == "error"])

import copy  # noqa: E402

unsupported = copy.deepcopy(good)
unsupported["hunt_result"]["evidence_summary"] = {"benign_supporting": []}
report(
    "benign with no supporting evidence is rejected",
    any("supported explanation" in i.message for i in validate_result(unsupported)),
)
uncited = copy.deepcopy(good)
uncited["hunt_result"]["step_results"][0].pop("evidence")
report("explanation without citation is rejected", any("citation" in i.message for i in validate_result(uncited)))
unexamined = copy.deepcopy(good)
unexamined["hunt_result"]["step_results"][0].update({"answer_status": "not_applicable", "assessment": "benign"})
report(
    "unexamined telemetry cannot be called benign",
    any("not evidence of benignity" in i.message for i in validate_result(unexamined)),
)
report(
    "bad vocabulary is rejected",
    any("not in" in i.message for i in validate_result({"hunt_result": {"hunt": "k", "disposition": "probably-fine"}})),
)

print("\nparser robustness + lint completeness")
_BT, _BT4 = "`" * 3, "`" * 4
# A ```` fence preserves an inner ``` instead of truncating the body.
_fence = f"---\nhypothesis: x\ntlp: green\n---\n# t\n## do\n{_BT4}action target=t\n{_BT}\nkept\n{_BT}\n{_BT4}\n→ end\n"
_do = next(s for s in parse_markdown(_fence).steps if s.slug == "do")
report("nested fence preserves body (no truncation)", "kept" in _do.body)
# Action gating: credit for a preceding decision; warn only without one.
_gated = f"---\nhypothesis: x\ntlp: green\n---\n# t\n## d\nif: `x`\nthen: → a\nelse: → end\n## a\n{_BT}action target=t\nisolate\n{_BT}\n→ end\n"
_bare = f"---\nhypothesis: x\ntlp: green\n---\n# t\n## a\n{_BT}action target=t\nisolate\n{_BT}\n→ end\n"
report("action after a decision isn't flagged ungated", not any("not gated" in str(i) for i in validate_markdown(_gated, profile="format")))
report("ungated action with no decision IS flagged", any("not gated" in str(i) for i in validate_markdown(_bare, profile="format")))
# Variable def-before-use / undeclared parameter.
_undecl = f"---\nhypothesis: x\ntlp: green\nparameters: {{lookback: {{type: duration}}}}\n---\n# t\n## q\n{_BT}kql target=s params=(d=nope)\nx {{{{d}}}}\n{_BT}\n→ end\n"
report("undeclared parameter source is an error", any("not declared" in str(i) for i in validate_markdown(_undecl, profile="format") if i.level == "error"))

print()
if failures:
    print(f"FAILED: {len(failures)} check(s) — {', '.join(failures[:5])}")
    raise SystemExit(1)
print("All checks passed.")
