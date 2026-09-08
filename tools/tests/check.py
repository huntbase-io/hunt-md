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

print("\npassthrough — unknown frontmatter keys and step attrs survive every exporter (SPEC §2)")
from huntmd.core import effective_guardrails as _eg  # noqa: E402

#: Frontmatter keys an exporter carries natively (and may normalise: label order,
#: regenerated references, materialised guardrails). Everything *else* must come
#: back byte-equal — that is the passthrough contract.
_NATIVE_FM = {"id", "type", "name", "labels", "tlp", "severity", "hypothesis", "references", "parameters", "targets",
              "guardrails", "created", "modified", "created_by", "x_cacao_source"}


def _norm(v):
    """Folded scalars re-emit with different trailing whitespace; that is not drift."""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return v


def passthrough_fingerprint(md: str) -> dict:
    pb = parse_markdown(md)
    return _norm({
        "frontmatter": {k: v for k, v in pb.meta.items() if k not in _NATIVE_FM},
        "targets": pb.meta.get("targets"),
        "parameters": pb.meta.get("parameters"),
        "guardrails": _eg(pb.meta),
        # parallel/group are authoring sugar, not nodes (documented loss on the definition path)
        "attrs": {s.slug: {k: v for k, v in s.attrs.items() if k != "cacao_id"} for s in pb.steps if s.kind not in ("parallel", "group")},
        "portable": {s.slug: s.portable for s in pb.steps if s.portable},
    })


def check_passthrough(name: str, md: str) -> None:
    before = passthrough_fingerprint(md)
    for label, fn in (
        ("cacao", lambda m: cacao_to_markdown(markdown_to_cacao(m))),
        ("definition", lambda m: definition_to_markdown(markdown_to_definition(m))),
        ("markdown", lambda m: __import__("huntmd.core", fromlist=["playbook_to_markdown"]).playbook_to_markdown(parse_markdown(m))),
    ):
        try:
            after = passthrough_fingerprint(fn(md))
        except Exception as exc:  # noqa: BLE001
            report(f"{name} passthrough via {label}", False, f"{type(exc).__name__}: {exc}")
            continue
        drift = [k for k in before if before[k] != after[k]]
        detail = ""
        if drift:
            k = drift[0]
            if isinstance(before[k], dict) and isinstance(after[k], dict):
                keys = sorted({kk for kk in set(before[k]) | set(after[k]) if before[k].get(kk) != after[k].get(kk)})
                detail = f"{k} differs at {keys[:3]}: {[(before[k].get(kk), after[k].get(kk)) for kk in keys[:1]]}"[:300]
            else:
                detail = f"{k}: {before[k]!r} -> {after[k]!r}"[:300]
        report(f"{name} passthrough via {label}", not drift, detail)


for path in hunts:
    check_passthrough(path.name, path.read_text(encoding="utf-8"))

# A hunt that uses keys no exporter knows, at every level: a frontmatter block
# from a future spec revision, a private extension on a target, Tier-2 attrs on
# a query, a decision, a task and an action, and an agent step with in/out.
_unknown = """---
type: investigation
name: passthrough fixture
labels: [hunt, attack.t1000]
tlp: green
severity: low
hypothesis: x
future_block:
  nested: {a: 1, b: [x, y]}
  text: keep me
private_ext: verbatim
parameters:
  lookback: {type: duration, default: "7d"}
targets:
  siem: {category: siem, name: SIEM, vendor_ext: {product: p}, telemetry: [identity]}
  hunter: {agent: true, name: Hunt agent}
  tier2: {role: analyst, name: Analyst}
---

# passthrough fixture

## q
```kql target=siem params=(days=lookback) out=$rows
~~~yaml
notes: collected via raw accessor
reads: [a, b]
~~~
x {{days}}
```

## d
~~~yaml
owner: pki
~~~
if: `q.rows > 0`
then: → a
else: → t

## a
```agent target=hunter in=[$rows] out=$verdict
~~~yaml
budget: 200
~~~
objective: o
tools: [siem]
max_iterations: 2
context: [q]
```

## t
```manual target=tier2
~~~yaml
sla: 4h
~~~
review
```
→ end

## act
```action target=siem
~~~yaml
approval: required
track: containment
severity_note: high
~~~
contain
```
→ end
"""
check_passthrough("unknown-keys fixture", _unknown)
report(
    "unknown frontmatter reaches the definition verbatim",
    markdown_to_definition(_unknown)["hunt"]["meta"]["x_hunt_frontmatter"]["future_block"]["nested"]["b"] == ["x", "y"],
)
report(
    "unknown step attrs reach the definition verbatim",
    next(n for n in markdown_to_definition(_unknown)["nodes"] if n["id"] == "q")["primitive_config"]["x_hunt_attrs"]["notes"] == "collected via raw accessor",
)
report(
    "unknown frontmatter reaches the CACAO export verbatim",
    markdown_to_cacao(_unknown)["x_hunt"]["frontmatter"]["private_ext"] == "verbatim",
)

print("\nbackward compatibility — frozen 0.5 hunts lint with the same errors and warnings (CHANGELOG rule 1)")
# These are the repo hunts exactly as they were at 0.5. New tooling may add
# info-level notes; it must not add or remove an error or a warning.
_EXPECTED_05 = {
    ("kerberoasting-0.5.md", "format"): [],
    ("kerberoasting-0.5.md", "huntbase"): ["route-by-verdict: switch: compiles to chained binary checkpoints on Huntbase"],
    ("scattered-spider-identity-takeover-0.5.md", "format"): [],
    ("scattered-spider-identity-takeover-0.5.md", "huntbase"): [],
}
for (fname, prof), expected in _EXPECTED_05.items():
    fx = ROOT / "tools" / "tests" / "fixtures" / fname
    got = [f"{i.slug}: {i.message}" for i in validate_markdown(fx.read_text(encoding="utf-8"), profile=prof) if i.level in ("error", "warn")]
    report(f"{fname} [{prof}] unchanged errors/warnings", got == expected, f"{got}")
    # …and still converts + round-trips
    try:
        _rt = parse_markdown(cacao_to_markdown(markdown_to_cacao(fx.read_text(encoding="utf-8"))))
        ok = bool(_rt.steps)
    except Exception as exc:  # noqa: BLE001
        ok = False
    report(f"{fname} still converts", ok)

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
# SPEC §8.1 shows the per-step override as a *trailing* ~~~yaml block inside the agent fence.
_trailing = base.format(extra="").replace("max_iterations: 2\n", "max_iterations: 2\n~~~yaml\nguardrails: { evidence: citation_required }\n~~~\n")
_tstep = parse_markdown(_trailing).steps[0]
report(
    "trailing ~~~yaml inside an agent fence parses (SPEC §8.1 form)",
    _tstep.attrs.get("guardrails") == {"evidence": "citation_required"} and _tstep.attrs.get("max_iterations") == 2,
    f"attrs={_tstep.attrs}",
)
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
report("legacy misp: classification keys get an info-level 'moved' notice", any(i.level == "info" and "moved to hunt.trigger" in i.message for i in validate_markdown(_badmisp, profile="misp")))

print("\nhunt: block + telemetry planes (SPEC §3.1, §6)")
_hb = "---\nhypothesis: x\ntlp: green\nlabels: [attack.t1000]\nhunt: {{trigger: {trig}, handoff: promote-to-detection, justification: 'PCI scope', assets: [cardholder-db], review_by: {rb}}}\ntargets:\n  siem: {{category: siem, name: SIEM{tele}}}\n---\n# t\n## q\n```kql target=siem role=detection-candidate\nx\n```\n→ end\n"
_good_hb = _hb.format(trig="crown-jewel", rb="2027-01-01", tele=", telemetry: [identity]")
report("well-formed hunt: block + declared telemetry lints clean", not [i for i in validate_markdown(_good_hb, profile="format") if i.level != "info"], str(validate_markdown(_good_hb, profile="format")))
report("hunt.trigger off-vocabulary warns (never rejects)", any(i.level == "warn" and "hunt.trigger" in i.message for i in validate_markdown(_hb.format(trig="vibes", rb="2027-01-01", tele=", telemetry: [identity]"), profile="format")))
report("hunt.review_by must be an ISO date", any("review_by" in i.message for i in validate_markdown(_hb.format(trig="crown-jewel", rb="soon", tele=", telemetry: [identity]"), profile="format")))
report("a siem target with no telemetry plane is an info under the default profile", any(i.level == "info" and "names a store" in i.message for i in validate_markdown(_hb.format(trig="crown-jewel", rb="2027-01-01", tele=""), profile="format")))
report("…and a warning under --profile quality", any(i.level == "warn" and "names a store" in i.message for i in validate_markdown(_hb.format(trig="crown-jewel", rb="2027-01-01", tele=""), profile="quality")))
report("an off-vocabulary plane warns", any("telemetry 'mainframe'" in i.message for i in validate_markdown(_hb.format(trig="crown-jewel", rb="2027-01-01", tele=", telemetry: [mainframe]"), profile="format")))
report("hunt: classification drives the hunt-ex tags", {'hunt-ex:trigger="crown-jewel"', 'hunt-ex:handoff="promote-to-detection"', 'hunt-ex:telemetry="identity"'} <= {t["name"] for t in markdown_to_misp(_good_hb)["Event"]["Tag"]})
report("hunt: block reaches the definition first-class", markdown_to_definition(_good_hb)["hunt"]["meta"]["hunt"]["trigger"] == "crown-jewel")
from huntmd.core import LANGUAGES, LANGUAGE_TO_HUNT_EX, HUNT_EX_VOCAB  # noqa: E402
report("every language maps to a HUNT-EX query-language value", all(hx in HUNT_EX_VOCAB["query-language"] for _, hx, _ in LANGUAGES) and LANGUAGE_TO_HUNT_EX["kql"] == "kusto")
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
    "foreign MISP event → draft: kql + sigma queries, ATT&CK label, tlp, finding as review task, hunt: + telemetry on targets",
    not _ferr
    and sorted(s.lang for s in _fpb.steps if s.kind == "query") == ["kql", "sigma"]
    and "attack.t1528" in _fpb.meta["labels"]
    and _fpb.meta["tlp"] == "amber"
    and any(s.kind == "task" for s in _fpb.steps)
    and all(t.get("telemetry") == "saas" for t in _fpb.meta["targets"].values() if t.get("category"))
    and _fpb.meta["hunt"]["trigger"] == "sector-alert"
    and _fpb.meta["provenance"]["source"] == {"system": "misp", "ref": "11111111-2222-3333-4444-555555555555"},
    "; ".join(_ferr[:2]) or _fmd[:300],
)
for fx in sorted((ROOT / "examples" / "misp-export").glob("*.json")):
    fev = json.loads(fx.read_text(encoding="utf-8"))
    fmd = misp_to_markdown(fev)
    ferr = [str(i) for i in validate_markdown(fmd, profile="format") if i.level == "error"]
    report(f"examples/misp-export/{fx.name} imports + lints", is_misp_event(fev) and not ferr, "; ".join(ferr[:2]))
report("attachment round-trip decodes utf-8", base64.b64decode(next(a["data"] for a in _ev["Attribute"] if a["type"] == "attachment")).decode() == _kb)

print("\nrationale, analysis, provenance (SPEC §3.1, §3.6)")
_pv = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
rationale: why this hypothesis
analysis: pivot from A to B, baseline C
provenance:
  authors: [{{name: Hunt team, org: Example}}, Solo Analyst]
  source: {{system: {system}, ref: abc, imported: 2026-09-01}}
  generated: {{by: pipeline, model: m, from: "https://x", gates: [{gate}]}}
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
---
# t
## q
```kql target=siem
x
```
→ end
"""
_pv_ok = _pv.format(system="misp", gate="dry-run")
report("well-formed provenance lints clean", not [i for i in validate_markdown(_pv_ok, profile="format") if i.level != "info"], str(validate_markdown(_pv_ok, profile="format")))
report("provenance.source.system off-vocabulary warns", any("source.system" in i.message for i in validate_markdown(_pv.format(system="carrier-pigeon", gate="lint"), profile="format")))
report("generated.gates off-vocabulary warns", any("gates 'vibes'" in i.message for i in validate_markdown(_pv.format(system="url", gate="vibes"), profile="format")))
_pv_ev = markdown_to_misp(_pv_ok)["Event"]
_pv_ctx = next(o for o in _pv_ev["Object"] if o["name"] == "threat-hunt-context")
_pv_hyp = next(o for o in _pv_ev["Object"] if o["name"] == "threat-hunt-hypothesis")
report("provenance.authors export as MISP contributors", sorted(a["value"] for a in _pv_ctx["Attribute"] if a["object_relation"] == "contributor") == ["Hunt team / Example", "Solo Analyst"])
report("rationale + analysis export on the hypothesis object (not a synthesised summary)", {a["object_relation"]: a["value"] for a in _pv_hyp["Attribute"]}.get("analysis") == "pivot from A to B, baseline C" and {a["object_relation"]: a["value"] for a in _pv_hyp["Attribute"]}.get("rationale") == "why this hypothesis")
_pv_rt = parse_markdown(cacao_to_markdown(markdown_to_cacao(_pv_ok)))
report("rationale/analysis/provenance survive md → CACAO → md", _pv_rt.meta.get("provenance") == parse_markdown(_pv_ok).meta["provenance"] and _pv_rt.meta.get("rationale") == "why this hypothesis")
report("provenance.authors seeds the CACAO created_by identity", markdown_to_cacao(_pv_ok)["created_by"] != markdown_to_cacao(_pv_ok.replace("Hunt team", "Other team"))["created_by"])

print("\nscenario + coverage (SPEC §3.4)")
_sc = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
scenario:
  stages:
    - {{slug: s1, techniques: [T1136.002]}}
    - {{slug: s2, techniques: [{tech}]}}
coverage:
  - {{stage: s1, status: covered, steps: [{step}]}}
{s2cov}---
# t
## q
```kql target=siem
x
```
→ end
"""
_sc_ok = _sc.format(tech="T1649", step="q", s2cov="  - {stage: s2, status: not_visible, reason: no sign-in logs}\n")
report("well-formed scenario + coverage lints clean", not [i for i in validate_markdown(_sc_ok, profile="format") if i.level == "error"], str(validate_markdown(_sc_ok, profile="format")))
report("a stage with no coverage entry is an error", any("has no coverage entry" in i.message for i in validate_markdown(_sc.format(tech="T1649", step="q", s2cov=""), profile="format")))
report("covered must name a real step", any("does not exist" in i.message for i in validate_markdown(_sc.format(tech="T1649", step="nope", s2cov="  - {stage: s2, status: covered, steps: [q]}\n"), profile="format")))
report("not_visible without a reason warns", any("no reason" in i.message for i in validate_markdown(_sc.format(tech="T1649", step="q", s2cov="  - {stage: s2, status: not_visible}\n"), profile="format")))
report("a malformed technique id warns", any("not a Txxxx" in i.message for i in validate_markdown(_sc.format(tech="privesc", step="q", s2cov="  - {stage: s2, status: out_of_scope, reason: r}\n"), profile="format")))
report("an unknown coverage stage is an error", any("not in scenario.stages" in i.message for i in validate_markdown(_sc_ok.replace("stage: s1", "stage: s9"), profile="format")))
report("scenario/coverage reach the definition first-class", markdown_to_definition(_sc_ok)["hunt"]["meta"]["coverage"][0]["status"] == "covered")

print("\nblind spots (SPEC §3.5, §7.2)")
_bs = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
blind_spots:
  - {{id: no-dns, requires: dns logs, risk: tunnelling stays invisible}}
---
# t
## judge
if~: "looks bad" (confidence: high, judge=a)
then: → act
indeterminate: → review
unavailable: → review (blind_spot: {ref})
else: → close
## act
```manual target=a
x
```
→ end
## review
```manual target=a
x
```
→ end
## close
```manual target=a
x
```
→ end
"""
_bs_ok = _bs.format(ref="no-dns")
_bs_pb = parse_markdown(_bs_ok)
report("unavailable: (blind_spot: id) parses to the step attr + edge", _bs_pb.steps[0].attrs.get("blind_spot") == "no-dns" and any(e.branch == "on_unavailable" and e.to == "review" for e in _bs_pb.edges))
report("well-formed blind_spots lints clean", not [i for i in validate_markdown(_bs_ok, profile="format") if i.level == "error"], str(validate_markdown(_bs_ok, profile="format")))
report("an undeclared blind_spot reference is an error", any("not declared" in i.message for i in validate_markdown(_bs.format(ref="nope"), profile="format")))
report("a blind spot with no risk warns", any("no risk" in i.message for i in validate_markdown(_bs_ok.replace(", risk: tunnelling stays invisible", ""), profile="format")))
report("unavailable: without a blind spot warns under --profile quality", any("no recorded cost" in i.message for i in validate_markdown(_bs_ok.replace(" (blind_spot: no-dns)", ""), profile="quality")))
report("…and not under --profile format", not any("no recorded cost" in i.message for i in validate_markdown(_bs_ok.replace(" (blind_spot: no-dns)", ""), profile="format")))
from huntmd.core import playbook_to_markdown as _p2m  # noqa: E402
report("blind_spot annotation survives md → md", "(blind_spot: no-dns)" in _p2m(_bs_pb))
report("blind_spot annotation survives md → CACAO → md", parse_markdown(cacao_to_markdown(markdown_to_cacao(_bs_ok))).steps[0].attrs.get("blind_spot") == "no-dns")
report("blind_spot annotation survives md → definition → md", next(s for s in parse_markdown(definition_to_markdown(markdown_to_definition(_bs_ok))).steps if s.slug == "judge").attrs.get("blind_spot") == "no-dns")

print("\nquery verification contract + silence (SPEC §5.5, §5.6)")
_qc = """---
hypothesis: x
tlp: {tlp}
labels: [attack.t1000]
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
  tier2: {{role: analyst, name: Analyst}}
---
# t
## q
```kql target=siem
~~~yaml
source: SecurityEvent
reads: [EventID, Account]
verified: {verified}
verified_at: 2026-09-07
expected: rows with EventID 4769
silence: {silence}
~~~
x
```
## d
if: `q.rows > 0`
then: → review
else: → {els}
## review
```manual target=tier2
x
```
→ end
"""
_qc_ok = _qc.format(tlp="green", verified="dry-run", silence="not_evidence_of_absence", els="review")
report("well-formed contract lints clean", not [i for i in validate_markdown(_qc_ok, profile="format") if i.level != "info"], str(validate_markdown(_qc_ok, profile="format")))
report("verified off-vocabulary warns", any("verified 'maybe'" in i.message for i in validate_markdown(_qc_ok.replace("verified: dry-run", "verified: maybe"), profile="format")))
report("verified: none on a tlp: clear hunt warns", any("public content" in i.message for i in validate_markdown(_qc.format(tlp="clear", verified="none", silence="not_evidence_of_absence", els="review"), profile="format")))
report("silence off-vocabulary warns", any("silence 'maybe'" in i.message for i in validate_markdown(_qc_ok.replace("silence: not_evidence_of_absence", "silence: maybe"), profile="format")))
report("else: → end on a not_evidence_of_absence source warns", any("closes the hunt on silence" in i.message for i in validate_markdown(_qc.format(tlp="green", verified="dry-run", silence="not_evidence_of_absence", els="end"), profile="format")))
report("…but not when the source's silence is evidence", not any("closes the hunt on silence" in i.message for i in validate_markdown(_qc.format(tlp="green", verified="dry-run", silence="evidence_of_absence", els="end"), profile="format")))
_nosil = _qc.format(tlp="green", verified="dry-run", silence="x", els="end").replace("silence: x\n", "")
report("…and not when silence: was never written (0.5 hunts lint as before)", not any("closes the hunt on silence" in i.message for i in validate_markdown(_nosil, profile="format")))
_pc = next(n for n in markdown_to_definition(_qc_ok)["nodes"] if n["id"] == "q")["primitive_config"]
report("contract keys are named primitive_config keys for the runtime", _pc.get("reads") == ["EventID", "Account"] and _pc.get("verified") == "dry-run" and _pc.get("silence") == "not_evidence_of_absence" and "x_hunt_attrs" not in _pc)
report("contract survives md → definition → md", parse_markdown(definition_to_markdown(markdown_to_definition(_qc_ok))).steps[0].attrs.get("reads") == ["EventID", "Account"])

print("\nrelated hunts + series (SPEC §3.8)")
_sr = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
series: {{slug: chain, index: {idx}, total: {tot}, title: part}}
related:
  - {{hunt: {ref}, relation: {rel}{reason}}}
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
---
# t
## q
```kql target=siem
x
```
→ end
"""
_sr_ok = _sr.format(idx=2, tot=3, ref="other-hunt", rel="precedes", reason="")
report("well-formed series + related lints clean", not [i for i in validate_markdown(_sr_ok, profile="format") if i.level in ("error", "warn")], str(validate_markdown(_sr_ok, profile="format")))
report("index above total is an error", any("exceeds total" in i.message for i in validate_markdown(_sr.format(idx=4, tot=3, ref="o", rel="precedes", reason=""), profile="format")))
report("an off-vocabulary relation warns", any("relation 'vibes'" in i.message for i in validate_markdown(_sr.format(idx=1, tot=2, ref="o", rel="vibes", reason=""), profile="format")))
report("supersedes without a reason warns", any("with no reason" in i.message for i in validate_markdown(_sr.format(idx=1, tot=2, ref="o", rel="supersedes", reason=""), profile="format")))
report("…and is quiet with one", not any("with no reason" in i.message for i in validate_markdown(_sr.format(idx=1, tot=2, ref="o", rel="supersedes", reason=", reason: replaced"), profile="format")))
report("a navigational slug that names nothing in the library warns", any(i.level == "warn" and "cannot follow it" in i.message for i in validate_markdown(_sr_ok, profile="format", bundle={"kerberoasting"})))
report("an unwritten alternative is only an info note", [i.level for i in validate_markdown(_sr.format(idx=1, tot=1, ref="not-written-yet", rel="out-of-scope-alternative", reason=", reason: needs network telemetry"), profile="format", bundle={"kerberoasting"}) if "not in this library yet" in i.message] == ["info"])
report("…and is quiet when it resolves", not any("not a hunt in this library" in i.message for i in validate_markdown(_sr_ok, profile="format", bundle={"other-hunt"})))
report("a URL reference is never checked against the library", not any("not a hunt" in i.message for i in validate_markdown(_sr.format(idx=1, tot=2, ref="https://x/y.md", rel="sibling", reason=""), profile="format", bundle=set())))
report("series/related survive md → CACAO → md", parse_markdown(cacao_to_markdown(markdown_to_cacao(_sr_ok))).meta["series"]["index"] == 2)
_sr_ev = markdown_to_misp(_sr_ok)["Event"]
report("the hypothesis id follows the series index (H2 for part 2)", any(a["object_relation"] == "hypothesis-id" and a["value"] == "H2" for o in _sr_ev["Object"] if o["name"] == "threat-hunt-hypothesis" for a in o["Attribute"]))
report("series + relation travel as annotated event attributes", any("part 2/3" in str(a.get("value")) for a in _sr_ev["Attribute"]) and any("related hunt (precedes)" in str(a.get("comment")) for a in _sr_ev["Attribute"]))

# A peer's event with two hypotheses: one file per hypothesis, wired together.
_multi = {
    "Event": {
        "info": "Two-part intrusion", "uuid": "22222222-3333-4444-5555-666666666666", "threat_level_id": "2",
        "Tag": [{"name": "tlp:green"}, {"name": 'hunt-ex:telemetry="endpoint"'}],
        "Attribute": [],
        "Object": [
            {"name": "threat-hunt-context", "uuid": "c0", "Attribute": [{"object_relation": "hunt-title", "value": "Two-part intrusion"}]},
            {"name": "threat-hunt-hypothesis", "uuid": "h1", "Attribute": [
                {"object_relation": "hypothesis-id", "value": "H1"},
                {"object_relation": "hypothesis", "value": "Loader persisted via a scheduled task"},
                {"object_relation": "attack-id", "value": "T1053.005"}]},
            {"name": "threat-hunt-hypothesis", "uuid": "h2", "Attribute": [
                {"object_relation": "hypothesis-id", "value": "H2"},
                {"object_relation": "hypothesis", "value": "Data left over a blockchain C2 channel"},
                {"object_relation": "attack-id", "value": "T1102"}]},
            {"name": "threat-hunt-query", "uuid": "q1", "Attribute": [
                {"object_relation": "hypothesis-id", "value": "H1"},
                {"object_relation": "query", "value": "DeviceProcessEvents | where x"},
                {"object_relation": "query-language", "value": "KQL"}]},
            {"name": "threat-hunt-query", "uuid": "q2", "Attribute": [
                {"object_relation": "hypothesis-id", "value": "H2"},
                {"object_relation": "query", "value": "DeviceNetworkEvents | where y"},
                {"object_relation": "query-language", "value": "KQL"}]},
        ],
    }
}
from huntmd.misp import hypothesis_count, misp_to_markdowns  # noqa: E402

report("hypothesis_count sees both", hypothesis_count(_multi) == 2)
_files = misp_to_markdowns(_multi)
report("a two-hypothesis event splits into two files", len(_files) == 2 and all(n.endswith(".md") for n, _ in _files), [n for n, _ in _files])
_p1, _p2 = (parse_markdown(x) for _, x in _files)
report("each file keeps its own hypothesis and its own query", "scheduled task" in str(_p1.meta["hypothesis"]) and "blockchain" in str(_p2.meta["hypothesis"]) and "DeviceProcessEvents" in _p1.steps[0].body and "DeviceNetworkEvents" in _p2.steps[0].body)
report("each file keeps only its own ATT&CK label", _p1.meta["labels"] == ["hunt", "attack.t1053.005"] and _p2.meta["labels"] == ["hunt", "attack.t1102"], f"{_p1.meta['labels']} / {_p2.meta['labels']}")
report("the parts are wired with series + sibling relations", _p1.meta["series"] == {"slug": "two-part-intrusion", "index": 1, "total": 2, "title": "Two-part intrusion"} and _p2.meta["related"][0]["relation"] == "sibling", str(_p1.meta.get("series")))
report("both split files lint clean", not [str(i) for pb_md in (x for _, x in _files) for i in validate_markdown(pb_md, profile="format") if i.level == "error"])
report("without --split the first hypothesis converts and the rest are declared", parse_markdown(misp_to_markdown(_multi)).meta["related"][0]["reason"].startswith("Data left"))

print("\nquery role + paired portable form (SPEC §5.8)")
_pf = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
hunt: {{handoff: {handoff}}}
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
---
# t
## q
```kql target=siem role={role}
Event | where EventID == 39
```
```{plang} portable
title: Weak certificate mapping
logsource: {{product: windows, service: system}}
detection:
  sel: {{EventID: 39}}
  condition: sel
```
→ end
"""
_pf_ok = _pf.format(handoff="promote-to-detection", role="detection-candidate", plang="sigma")
_pf_pb = parse_markdown(_pf_ok)
_pf_step = _pf_pb.steps[0]
report("the native fence still defines the step", _pf_step.lang == "kql" and _pf_step.target == "siem" and "EventID == 39" in _pf_step.body)
report("the portable fence attaches as a twin, not a redefinition", (_pf_step.portable or {}).get("language") == "sigma" and "logsource" in (_pf_step.portable or {}).get("body", ""))
report("role parses from the info string", _pf_step.attrs.get("role") == "detection-candidate")
report("well-formed role + portable lints clean", not [i for i in validate_markdown(_pf_ok, profile="format") if i.level in ("error", "warn")], str(validate_markdown(_pf_ok, profile="format")))
report("an unflagged second fence still replaces the query (0.5 behaviour intact)", parse_markdown(_pf_ok.replace("```sigma portable", "```sigma")).steps[0].lang == "sigma")
report("promote-to-detection with no detection-candidate warns", any("no query is marked role=detection-candidate" in i.message for i in validate_markdown(_pf.format(handoff="promote-to-detection", role="scoping", plang="sigma"), profile="format")))
report("…and does not warn for another handoff", not any("detection-candidate" in i.message and i.level == "warn" for i in validate_markdown(_pf.format(handoff="retire", role="scoping", plang="sigma"), profile="format")))
report("an off-vocabulary role warns", any("role 'vibes'" in i.message for i in validate_markdown(_pf.format(handoff="retire", role="vibes", plang="sigma"), profile="format")))
report("a non-portable language in a portable block warns", any("not a portable detection format" in i.message for i in validate_markdown(_pf.format(handoff="retire", role="scoping", plang="kql"), profile="format")))
report("role + portable survive md → md", (parse_markdown(_p2m(_pf_pb)).steps[0].portable or {}).get("language") == "sigma" and parse_markdown(_p2m(_pf_pb)).steps[0].attrs.get("role") == "detection-candidate")
report("role + portable survive md → CACAO → md", (parse_markdown(cacao_to_markdown(markdown_to_cacao(_pf_ok))).steps[0].portable or {}).get("language") == "sigma")
_pf_pc = next(n for n in markdown_to_definition(_pf_ok)["nodes"] if n["id"] == "q")["primitive_config"]
report("role + portable are named primitive_config keys", _pf_pc.get("role") == "detection-candidate" and _pf_pc.get("portable", {}).get("language") == "sigma")
report("role + portable survive md → definition → md", (parse_markdown(definition_to_markdown(markdown_to_definition(_pf_ok))).steps[0].portable or {}).get("language") == "sigma")
_pf_ev = markdown_to_misp(_pf_ok)["Event"]
_pf_sigma = [o for o in _pf_ev["Object"] if o["name"] == "sigma"]
_pf_q = next(o for o in _pf_ev["Object"] if o["name"] == "threat-hunt-query")
report("the portable twin exports as MISP's own sigma object", len(_pf_sigma) == 1 and any(a["object_relation"] == "sigma" and "logsource" in a["value"] for a in _pf_sigma[0]["Attribute"]), [o["name"] for o in _pf_ev["Object"]])
report("…linked derived-from the query and tests the hypothesis", _pf_sigma and {r["relationship_type"] for r in _pf_sigma[0]["ObjectReference"]} == {"derived-from", "tests"} and any(r["referenced_uuid"] == _pf_q["uuid"] for r in _pf_sigma[0]["ObjectReference"]))
report("…and its rule name comes from the sigma title", _pf_sigma and any(a["object_relation"] == "sigma-rule-name" and a["value"] == "Weak certificate mapping" for a in _pf_sigma[0]["Attribute"]))
report("md → MISP → md stays byte-exact with a portable twin", misp_to_markdown(json.loads(json.dumps(markdown_to_misp(_pf_ok)))) == _pf_ok)
_pf_stripped = json.loads(json.dumps(markdown_to_misp(_pf_ok)))
_pf_stripped["Event"]["Attribute"] = [a for a in _pf_stripped["Event"]["Attribute"] if a["type"] != "attachment"]
_pf_draft = parse_markdown(misp_to_markdown(_pf_stripped))
report("objects-only import restores the sigma object as the query's twin, not a separate step", len([s for s in _pf_draft.steps if s.kind == "query"]) == 1 and (_pf_draft.steps[0].portable or {}).get("language") == "sigma", [(s.slug, s.kind, bool(s.portable)) for s in _pf_draft.steps])

print("\ntyped parameters + indicator provenance (SPEC §3.7)")
_tp = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
parameters:
  lookback: {{type: duration, default: 7d}}
  c2:
    type: {ptype}
    default: {default}
{from_}targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
---
# t
## q
```kql target=siem params=(days=lookback, list=c2)
x {{{{days}}}} {{{{list}}}}
```
→ end
"""
_from_ok = "    from: {kind: article, ref: 'https://x', observed: 2026-05-11}\n"
_tp_ok = _tp.format(ptype="list[domain]", default='["a.example"]', from_=_from_ok)
report("typed indicator list with provenance lints clean", not [i for i in validate_markdown(_tp_ok, profile="format") if i.level != "info"], str(validate_markdown(_tp_ok, profile="format")))
report("an indicator list with no from: warns", any("no from:" in i.message for i in validate_markdown(_tp.format(ptype="list[domain]", default='["a.example"]', from_=""), profile="format")))
report("an unknown list member type warns", any("list member type 'ipv7'" in i.message for i in validate_markdown(_tp.format(ptype="list[ipv7]", default='["a"]', from_=_from_ok), profile="format")))
report("an unknown scalar type warns", any("is not a known type" in i.message for i in validate_markdown(_tp.format(ptype="vibes", default='"a"', from_=""), profile="format")))
report("a list type with a scalar default warns", any("default is not a list" in i.message for i in validate_markdown(_tp.format(ptype="list[domain]", default='"a.example"', from_=_from_ok), profile="format")))
report("from.kind off-vocabulary warns", any("from.kind" in i.message for i in validate_markdown(_tp_ok.replace("kind: article", "kind: hearsay"), profile="format")))
report("stale indicators warn under --profile quality", any("indicators observed" in i.message for i in validate_markdown(_tp_ok.replace("observed: 2026-05-11", "observed: 2020-01-01"), profile="quality")))
_tp_cacao = markdown_to_cacao(_tp_ok)["playbook_variables"]["__c2__"]
report("CACAO carries the list type and its provenance", _tp_cacao["x_hunt_type"] == "list[domain]" and _tp_cacao["x_hunt_from"]["ref"] == "https://x" and _tp_cacao["value"] == "a.example")
_tp_rt = parse_markdown(cacao_to_markdown(markdown_to_cacao(_tp_ok))).meta["parameters"]["c2"]
report("type, list default and from: survive md → CACAO → md", _tp_rt["type"] == "list[domain]" and _tp_rt["default"] == ["a.example"] and str(_tp_rt["from"]["observed"]) == "2026-05-11", str(_tp_rt))
report("a list of tool paths needs no from: (only volatile members rot)", not any("with no from:" in i.message for i in validate_markdown(_tp.format(ptype="list[path]", default="[a.exe]", from_=""), profile="format")))
report("…and a year-old tool list is not called stale", not any("indicators observed" in i.message for i in validate_markdown(_tp.format(ptype="list[path]", default="[a.exe]", from_="    from: {kind: advisory, ref: AA, observed: 2020-01-01}\n"), profile="quality")))

print("\nprevalence + baseline (SPEC §5.7)")
_pv7 = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
---
# t
## q
```kql target=siem
~~~yaml
prevalence: {{key: {key}, by: host, rare_below: {rb}}}
baseline: {{window: 14d, compare: {cmp}}}
~~~
x
```
→ end
"""
_pv7_ok = _pv7.format(key="[proc]", rb=3, cmp="first_seen")
report("well-formed prevalence/baseline lints clean", not [i for i in validate_markdown(_pv7_ok, profile="format") if i.level != "info"], str(validate_markdown(_pv7_ok, profile="format")))
report("baseline.compare off-vocabulary warns", any("baseline.compare" in i.message for i in validate_markdown(_pv7.format(key="[proc]", rb=3, cmp="vibes"), profile="format")))
report("rare_below must be a positive integer", any("rare_below" in i.message for i in validate_markdown(_pv7.format(key="[proc]", rb=0, cmp="first_seen"), profile="format")))
report("prevalence.key must be a list", any("prevalence.key" in i.message for i in validate_markdown(_pv7.format(key="proc", rb=3, cmp="first_seen"), profile="format")))
_pc7 = next(n for n in markdown_to_definition(_pv7_ok)["nodes"] if n["id"] == "q")["primitive_config"]
report("prevalence/baseline are named primitive_config keys", _pc7.get("prevalence", {}).get("rare_below") == 3 and _pc7.get("baseline", {}).get("compare") == "first_seen")
report("prevalence survives md → CACAO → md", parse_markdown(cacao_to_markdown(markdown_to_cacao(_pv7_ok))).steps[0].attrs.get("prevalence", {}).get("by") == "host")
report("a hunt with no prevalence step warns under --profile quality", any("no prevalence step" in i.message for i in validate_markdown(_pv7_ok.replace("prevalence: {key: [proc], by: host, rare_below: 3}\n", "").replace("baseline: {window: 14d, compare: first_seen}\n", ""), profile="quality")))

print("\nquality profile (opt-in, SPEC §13)")
_ql = """---
hypothesis: x
tlp: green
labels: [attack.t1000]
hunt: {{justification: because}}
references: [{{name: blog{url}}}]
targets:
  siem: {{category: siem, name: SIEM, telemetry: [identity]}}
  hunter: {{agent: true, name: Hunt agent}}
  tier2: {{role: analyst, name: Analyst}}
---
# t
## q
```kql target=siem
{query}
```
## a
```agent target=hunter
objective: o
tools: [siem]
max_iterations: {iters}
context: [q, q, q]
```
## j
if~: "bad" (confidence: high, judge=hunter)
then: → {then_}
indeterminate: → review
else: → review
## review
```manual target=tier2
{task}
```
→ end
## act
```manual target=tier2
look
```
→ end
"""
_ioc = 'SecurityEvent | where Computer in ("a-host", "b-host", "c-host", "d-host", "e-host")'
_stack = "SecurityEvent | summarize c=count() by Computer"
_ql_ok = _ql.format(url=", url: https://x", query=_stack, iters=6, then_="act", task="review it")
report("a well-formed hunt is quiet under --profile quality", not [i for i in validate_markdown(_ql_ok, profile="quality") if i.level == "warn"], str(validate_markdown(_ql_ok, profile="quality")))
_q_ioc = validate_markdown(_ql.format(url=", url: https://x", query=_ioc, iters=6, then_="act", task="review it"), profile="quality")
report("an indicator-list query warns, and 'every query' warns when that is all there is", any("indicator list" in i.message and i.slug == "q" for i in _q_ioc) and any("every query is an indicator list" in i.message for i in _q_ioc))
report("…and the default profile says nothing", not any("indicator" in i.message for i in validate_markdown(_ql.format(url=", url: https://x", query=_ioc, iters=6, then_="act", task="review it"), profile="format")))
report("a fuzzy decision whose branches converge warns", any("changes nothing" in i.message for i in validate_markdown(_ql.format(url=", url: https://x", query=_stack, iters=6, then_="review", task="review it"), profile="quality")))
report("a manual task with a containment verb warns", any("gated" in i.message and "isolate" in i.message for i in validate_markdown(_ql.format(url=", url: https://x", query=_stack, iters=6, then_="act", task="isolate the host"), profile="quality")))
report("max_iterations below the context count warns", any("cannot finish" in i.message for i in validate_markdown(_ql.format(url=", url: https://x", query=_stack, iters=2, then_="act", task="review it"), profile="quality")))
report("a reference without a url warns", any("has no url" in i.message for i in validate_markdown(_ql.format(url="", query=_stack, iters=6, then_="act", task="review it"), profile="quality")))
report("a missing hunt.justification warns", any("no hunt.justification" in i.message for i in validate_markdown(_ql_ok.replace("hunt: {justification: because}\n", ""), profile="quality")))
report("stale verified_at warns", any("days old" in i.message for i in validate_markdown(_ql_ok.replace("```kql target=siem\n", "```kql target=siem\n~~~yaml\nverified: executed\nverified_at: 2020-01-01\n~~~\n"), profile="quality")))
for path in hunts:
    _qi = [str(i) for i in validate_markdown(path.read_text(encoding="utf-8"), profile="quality") if i.level == "warn"]
    report(f"{path.name} passes --profile quality", not _qi, "; ".join(_qi[:2]))

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
# §12.3 outcome / byproducts / handoff / period
_r123 = copy.deepcopy(good)
_r123["hunt_result"].update({"outcome": "hypothesis-confirmed-benign", "byproducts": ["detection-gap"], "handoff": "retire", "period": {"start": "2026-07-01T00:00:00Z", "end": "2026-07-14T00:00:00Z"}})
report("§12.3 fields lint clean when well-formed", not [i for i in validate_result(_r123) if i.level == "error"], str(validate_result(_r123)))
_bad_o = copy.deepcopy(_r123); _bad_o["hunt_result"]["outcome"] = "meh"
report("outcome off-vocabulary is an error", any("outcome 'meh'" in i.message for i in validate_result(_bad_o)))
_cb = copy.deepcopy(_r123); _cb["hunt_result"]["evidence_summary"] = {"benign_supporting": []}; _cb["hunt_result"]["disposition"] = "inconclusive"
report("confirmed-benign outcome needs benign evidence", any("confirmed-benign hypothesis needs" in i.message for i in validate_result(_cb)))
_mal = copy.deepcopy(_r123); _mal["hunt_result"].update({"disposition": "malicious", "outcome": "hypothesis-not-confirmed"})
report("malicious + not-confirmed is contradictory", any("contradict" in i.message or "malicious finding confirms" in i.message for i in validate_result(_mal)))
_per = copy.deepcopy(_r123); _per["hunt_result"]["period"] = {"start": "2026-07-14T00:00:00Z", "end": "2026-07-01T00:00:00Z"}
report("period start after end is an error", any("after period.end" in i.message for i in validate_result(_per)))
_gap = copy.deepcopy(_r123); _gap["hunt_result"]["telemetry_coverage"] = {"missing": [{"target": "edr", "impact": "x", "blind_spot": "no-edr"}]}
report("missing telemetry without data-source-gap byproduct warns", any("data-source-gap" in i.message for i in validate_result(_gap)))
_ev123 = markdown_to_misp(_kb, result=_r123)["Event"]
_t123 = {t["name"] for t in _ev123["Tag"]}
report("recorded outcome/byproducts/handoff drive the finding tags (no heuristic)", {'hunt-ex:outcome="hypothesis-confirmed-benign"', 'hunt-ex:byproduct="detection-gap"', 'hunt-ex:handoff="retire"'} <= _t123, str(sorted(_t123)))
_ctx123 = next(o for o in _ev123["Object"] if o["name"] == "threat-hunt-context")
report("period lands on the context object", any(a["object_relation"] == "period-start" and a["value"].startswith("2026-07-01") for a in _ctx123["Attribute"]))
_run_issues = validate_result(_run)
report("examples/results/kerberoasting-run.yaml lints clean with §12.3 fields", not [i for i in _run_issues if i.level == "error"], str(_run_issues))

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
