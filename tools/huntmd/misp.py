"""hunt.md IR ⇄ MISP event (HUNT-EX taxonomy + threat-hunt-* objects).

Implements the MISP profile described in ``../PROFILES.md`` §3. MISP is a
*sharing* target: the HUNT-EX taxonomy classifies a hunt for cross-organisation
search, and the four companion objects give it a structured, queryable shape —

    threat-hunt-context     ← frontmatter (title, purpose, data sources, tools)
    threat-hunt-hypothesis  ← ``hypothesis:`` + ATT&CK labels
    threat-hunt-query       ← one per ``query`` step (query text, language, target)
    threat-hunt-finding     ← a run result (SPEC §12), when one is supplied

What the objects cannot carry is the hunt's *control flow* — decisions, agent
steps, approval gates, dataflow. So the exporter also attaches the full hunt.md
source as an ``attachment`` attribute; a hunt-md-aware importer recovers the
exact source, while any MISP instance still gets the searchable objects and
tags. Importing an event authored elsewhere (objects only) yields a **draft**
hunt.md with ``TODO`` markers, exactly like the CACAO importer.

Identifiers are deterministic (``uuid5`` over the playbook id + relation, per
SPEC §10), so re-exporting an unchanged hunt yields a stable event.

Vocabularies come from upstream (misp-taxonomies/hunt-ex v4, misp-objects
threat-hunt-* v1) — see ``_HUNT_EX``. Unknown values are passed through with a
lint warning, never rejected.
"""

from __future__ import annotations

import base64
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from huntmd.core import (
    HUNT_EX_VOCAB,
    LANGUAGE_TO_HUNT_EX,
    ConversionError,
    Playbook,
    Step,
    hunt_block,
    parse_markdown,
    playbook_to_markdown,
    target_telemetry,
)

#: Stable namespace for all hunt.md-derived MISP identifiers (shared with CACAO).
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "hunt.md")

TAXONOMY = "hunt-ex"

#: HUNT-EX taxonomy (machinetag.json v4) — closed vocabularies per predicate (single source: core).
_HUNT_EX = HUNT_EX_VOCAB

#: misp-objects templates (name → (uuid, version, meta-category, description)).
#: The description is the template's own — MISP silently drops an object whose
#: ``description`` is empty, so it must be present and non-empty.
_TEMPLATES = {
    "threat-hunt-context": (
        "6dec94ff-b74b-4cab-ad38-3d3c8308bdb3",
        "1",
        "threat-hunting",
        "Metadata describing the purpose, methodology, and resourcing of a threat hunt. One instance per MISP event; corresponds to the Purpose and Equip sections of the hunt report.",
    ),
    "threat-hunt-hypothesis": (
        "4136cd18-3edd-49fb-90ba-24cbacacc662",
        "1",
        "threat-hunting",
        "A single testable hypothesis from the Scope and Execute sections of a hunt: its scoping decision, targeted ATT&CK technique(s), and analytic reasoning. One instance per hypothesis.",
    ),
    "threat-hunt-query": (
        "0fc943ec-c8fd-4311-b748-249bdef0f7d8",
        "1",
        "threat-hunting",
        "A platform-native hunting query used to test a hypothesis. Use this object for SPL, KQL, EQL, and similar query languages. When the detection logic is portable, prefer the standard MISP sigma or yara object instead and link it to the hypothesis with a 'tests' Object Reference.",
    ),
    "threat-hunt-finding": (
        "ce3ab17c-9ac5-47fb-bad5-48d368568437",
        "1",
        "threat-hunting",
        "The outcome of testing a hypothesis: conclusion, classification, and follow-up. Corresponds to the Feedback section of a hunt report. One instance per hypothesis.",
    ),
}

#: hunt.md query language (SPEC §5.1) → HUNT-EX ``query-language`` value (single source: core.LANGUAGES).
_LANG_TO_HUNT_EX = LANGUAGE_TO_HUNT_EX
#: The inverse, for import — HUNT-EX / object ``query-language`` → fence language.
_HUNT_EX_TO_LANG = {
    "kusto": "kql", "kql": "kql", "spl": "spl", "esql": "esql", "eql": "eql", "kibana-query": "esdsl", "aql": "aql",
    "xql": "xql", "sigma": "sigma", "yara": "yara", "yara-l": "yara-l", "stix-pattern": "stix", "stix pattern": "stix",
    "sql": "sql", "osquery sql": "osquery", "cql": "cql", "shell": "shell", "powershell": "powershell",
    "python": "python", "suricata-snort": "suricata",
}
#: hunt.md query language → the object's own ``query-language`` sane_default label.
_LANG_TO_OBJECT_LABEL = {
    "kql": "KQL", "kusto": "KQL", "spl": "SPL", "eql": "EQL", "osquery": "OSQuery SQL", "yara-l": "YARA-L",
    "stix": "STIX Pattern",
}

#: Run-result disposition (SPEC §12.1) → HUNT-EX ``outcome`` + finding ``outcome``.
_DISPOSITION_OUTCOME = {
    "malicious": ("hypothesis-confirmed-malicious", "True Positive"),
    "suspicious": ("inconclusive", "Inconclusive"),
    "potentially_benign": ("hypothesis-confirmed-benign", "Benign True Positive"),
    "benign": ("hypothesis-confirmed-benign", "Benign True Positive"),
    "inconclusive": ("inconclusive", "Inconclusive"),
}

#: HUNT-EX outcome → the finding object's own ``outcome`` label.
_OUTCOME_OBJECT_LABEL = {
    "hypothesis-confirmed-malicious": "True Positive",
    "hypothesis-confirmed-benign": "Benign True Positive",
    "hypothesis-not-confirmed": "False Positive",
    "inconclusive": "Inconclusive",
}

_ATTACK = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
_TLP_TAG = re.compile(r"^tlp:(clear|white|green|amber|amber\+strict|red)$", re.I)
_HUNT_EX_TAG = re.compile(rf'^{TAXONOMY}:([a-z-]+)="([^"]+)"$')

SOURCE_ATTACHMENT_COMMENT = "hunt.md source (exact; regenerate the objects from this, do not edit them)"


# --- helpers ------------------------------------------------------------------


def _playbook_uuid(pb: Playbook) -> uuid.UUID:
    pinned = pb.meta.get("id")
    if pinned:
        raw = str(pinned).split("--")[-1]
        try:
            return uuid.UUID(raw)
        except ValueError:
            return uuid.uuid5(_NS, str(pinned))
    return uuid.uuid5(_NS, pb.name or "untitled-hunt")


def _uid(ns: uuid.UUID, *parts: str) -> str:
    return str(uuid.uuid5(ns, ":".join(parts)))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tag(predicate: str, value: str) -> dict[str, str]:
    return {"name": f'{TAXONOMY}:{predicate}="{value}"'}


def _misp_block(pb: Playbook) -> dict[str, Any]:
    """The optional namespaced ``misp:`` frontmatter block (PROFILES §3)."""
    block = pb.meta.get("misp")
    return dict(block) if isinstance(block, dict) else {}


def _attack_ids(meta: dict[str, Any]) -> list[str]:
    out = []
    for label in meta.get("labels") or []:
        m = _ATTACK.match(str(label))
        if m:
            out.append(m.group(1).upper())
    return out


def _tlp(meta: dict[str, Any]) -> str | None:
    tlp = meta.get("tlp")
    return str(tlp).lower() if tlp else None


def _target_of(pb: Playbook, slug: str | None) -> dict[str, Any]:
    targets = pb.meta.get("targets") or {}
    t = targets.get(slug) if slug else None
    return t if isinstance(t, dict) else {}


def _bindings(target: dict[str, Any]) -> list[str]:
    """Product names from namespaced bindings (``huntbase: {product: …}`` etc.)."""
    products = []
    for key, val in target.items():
        if key in ("category", "name", "agent", "role", "individual", "model"):
            continue
        if isinstance(val, dict) and val.get("product"):
            products.append(str(val["product"]))
    return products


def _classification(pb: Playbook) -> dict[str, Any]:
    """``hunt:`` (SPEC §3.1), with the deprecated ``misp:`` keys honoured as a fallback."""
    return hunt_block(pb.meta)


def _telemetry(pb: Playbook) -> list[str]:
    """Planes from the targets (declared ``telemetry:`` or derived from category, SPEC §6).

    A ``misp.telemetry`` override is still honoured (deprecated in 0.6; the
    plane now lives on the target).
    """
    declared = _misp_block(pb).get("telemetry")
    if declared:
        return [str(v) for v in ([declared] if isinstance(declared, str) else declared)]
    seen: list[str] = []
    for t in (pb.meta.get("targets") or {}).values():
        if isinstance(t, dict):
            for tele in target_telemetry(t):
                if tele not in seen:
                    seen.append(tele)
    return seen


def _query_steps(pb: Playbook) -> list[Step]:
    return [s for s in pb.steps if s.kind == "query" and s.body.strip()]


def _step_description(s: Step) -> str:
    desc = s.attrs.get("description")
    return str(desc).strip() if desc else ""


# --- export: Playbook (+ result) → MISP event -----------------------------------


def _attr(relation: str, value: Any, *, type_: str = "text", uid: str, comment: str | None = None, **extra) -> dict:
    a: dict[str, Any] = {
        "uuid": uid,
        "object_relation": relation,
        "type": type_,
        "category": "Other" if type_ != "attachment" else "External analysis",
        "value": "" if value is None else str(value),
        "to_ids": False,
        "disable_correlation": True,
    }
    if comment:
        a["comment"] = comment
    a.update(extra)
    return a


#: Object relations that may legitimately repeat inside one object. Their attribute
#: ids include the value; every other relation's id is keyed on the relation alone,
#: so a re-export with a changed value *replaces* the attribute under ``events/edit``
#: instead of leaving the stale one beside it.
_MULTI_VALUED = {"data-source", "tool", "contributor", "attack-id"}


def _attr_uid(ns: uuid.UUID, obj_key: str, rel: str, value: Any) -> str:
    parts = ["attr", obj_key, rel] + ([str(value)] if rel in _MULTI_VALUED else [])
    return _uid(ns, *parts)


def _object(name: str, ns: uuid.UUID, key: str, attributes: list[dict], comment: str = "") -> dict[str, Any]:
    tmpl_uuid, version, category, description = _TEMPLATES[name]
    return {
        "uuid": _uid(ns, "object", key),
        "name": name,
        "meta-category": category,
        "description": description,
        "template_uuid": tmpl_uuid,
        "template_version": version,
        "comment": comment,
        "Attribute": attributes,
        "ObjectReference": [],
    }


def _reference(obj: dict, ns: uuid.UUID, relationship: str, target_uuid: str, comment: str = "") -> None:
    obj["ObjectReference"].append(
        {
            "uuid": _uid(ns, "ref", obj["uuid"], relationship, target_uuid),
            "object_uuid": obj["uuid"],
            "referenced_uuid": target_uuid,
            "relationship_type": relationship,
            "comment": comment,
        }
    )


def _context_object(pb: Playbook, ns: uuid.UUID, misp: dict, result: dict | None) -> dict:
    a = lambda rel, val, **kw: _attr(rel, val, uid=_attr_uid(ns, "context", rel, val), **kw)  # noqa: E731
    attrs = [a("hunt-title", pb.name or "Untitled hunt")]
    purpose = misp.get("purpose") or pb.description.strip() or pb.meta.get("hypothesis") or pb.name
    attrs.append(a("purpose", str(purpose).strip()))
    methodology = _classification(pb).get("methodology") or "structured-hypothesis-driven"
    attrs.append(a("methodology", methodology))
    status = misp.get("status") or ("Concluded" if result else "Planned")
    attrs.append(a("status", status))
    seen_ds: set[str] = set()
    tools: list[str] = []
    for slug, t in (pb.meta.get("targets") or {}).items():
        if not isinstance(t, dict) or t.get("agent") or t.get("role") or t.get("individual"):
            continue
        ds = str(t.get("name") or t.get("category") or slug)
        if ds not in seen_ds:
            seen_ds.add(ds)
            attrs.append(a("data-source", ds, comment=f"target: {slug} (category: {t.get('category', '?')})"))
        for product in _bindings(t):
            if product not in tools:  # MISP de-duplicates identical values within an object anyway
                tools.append(product)
    attrs.extend(a("tool", product) for product in tools)
    for c in dict.fromkeys(misp.get("contributors") or misp.get("contributor") or []):
        attrs.append(a("contributor", c))
    period = ((result or {}).get("hunt_result") or result or {}).get("period") if result else None
    period = period if isinstance(period, dict) else {}
    for rel, key in (("period-start", "start"), ("period-end", "end")):
        value = period.get(key) or misp.get(rel)
        if value:
            attrs.append(a(rel, value, type_="datetime"))
    return _object("threat-hunt-context", ns, "context", attrs)


def _hypothesis_object(pb: Playbook, ns: uuid.UUID, misp: dict, result: dict | None) -> dict:
    a = lambda rel, val, **kw: _attr(rel, val, uid=_attr_uid(ns, "hypothesis", rel, val), **kw)  # noqa: E731
    hyp = str(pb.meta.get("hypothesis") or "").strip()
    attrs = [
        a("hypothesis-id", "H1"),
        a("hypothesis", hyp or "TODO: hypothesis"),
        a("scope", "In-Scope"),
    ]
    for tid in _attack_ids(pb.meta):
        attrs.append(a("attack-id", tid))
    analysis = misp.get("analysis") or _flow_summary(pb)
    if analysis:
        attrs.append(a("analysis", analysis))
    if misp.get("rationale"):
        attrs.append(a("rationale", misp["rationale"]))
    attrs.append(a("status", "Tested" if result else "Not Started"))
    return _object("threat-hunt-hypothesis", ns, "hypothesis", attrs)


def _flow_summary(pb: Playbook) -> str:
    """One line per step — the analytic reasoning MISP has no graph for."""
    lines = []
    for s in pb.steps:
        if s.kind in ("group", "parallel"):
            continue
        what = _step_description(s)
        if not what:
            if s.kind == "decision":
                what = f"if {s.condition}" if s.condition else "decision"
            elif s.kind == "agent":
                what = str(s.attrs.get("objective") or "agent triage").strip()
            elif s.kind == "query":
                what = f"{s.lang or 'query'} against {s.target or '?'}"
            else:
                what = s.body.strip().splitlines()[0] if s.body.strip() else s.kind
        lines.append(f"- {s.slug} [{s.kind}]: {what}")
    return "\n".join(lines)


def _query_object(pb: Playbook, ns: uuid.UUID, s: Step) -> dict:
    a = lambda rel, val, **kw: _attr(rel, val, uid=_attr_uid(ns, f"query:{s.slug}", rel, val), **kw)  # noqa: E731
    lang = (s.lang or "").lower()
    attrs = [
        a("hypothesis-id", "H1"),
        a("query", s.body.rstrip("\n"), comment=f"hunt.md step: {s.slug}"),
        a("query-language", _LANG_TO_OBJECT_LABEL.get(lang, lang.upper() if lang else "Other")),
    ]
    target = _target_of(pb, s.target)
    if s.target:
        attrs.append(a("data-source", str(target.get("name") or s.target), comment=f"target: {s.target}"))
    for product in _bindings(target):
        attrs.append(a("platform", product))
    notes = []
    if _step_description(s):
        notes.append(_step_description(s))
    if s.params:
        notes.append("parameters: " + ", ".join(f"{{{{{k}}}}} ← {v}" for k, v in s.params.items()))
    if notes:
        attrs.append(a("comment", "\n".join(notes), type_="comment"))
    return _object("threat-hunt-query", ns, f"query:{s.slug}", attrs, comment=f"hunt.md step `{s.slug}`")


def _finding_object(pb: Playbook, ns: uuid.UUID, result: dict) -> tuple[dict, list[dict]]:
    """A ``threat-hunt-finding`` from a SPEC §12 run result, plus the outcome tags."""
    r = result.get("hunt_result") or result
    a = lambda rel, val, **kw: _attr(rel, val, uid=_attr_uid(ns, f"finding:{r.get('run', '')}", rel, val), **kw)  # noqa: E731
    disposition = str(r.get("disposition") or "inconclusive")
    hunt_ex_outcome, obj_outcome = _DISPOSITION_OUTCOME.get(disposition, ("inconclusive", "Inconclusive"))
    if disposition == "benign" and not (r.get("evidence_summary") or {}).get("benign_supporting"):
        hunt_ex_outcome = "hypothesis-not-confirmed"
    # A recorded outcome (SPEC §12.3) beats the disposition heuristic — the
    # runtime or analyst knows whether "not confirmed" or "confirmed benign".
    recorded = str(r.get("outcome") or "")
    outcome_note = ""
    if recorded in _HUNT_EX["outcome"]:
        hunt_ex_outcome = recorded
        obj_outcome = _OUTCOME_OBJECT_LABEL.get(recorded, obj_outcome)
    else:
        outcome_note = " Outcome inferred from the disposition (no outcome: recorded)."

    parts = [f"Disposition: {disposition} (confidence: {r.get('confidence', '?')}); run {r.get('run', '?')}.{outcome_note}"]
    period = r.get("period") if isinstance(r.get("period"), dict) else {}
    if period.get("start") or period.get("end"):
        parts.append(f"Period examined: {period.get('start', '?')} → {period.get('end', '?')}.")
    for sr in r.get("step_results") or []:
        exp = str(sr.get("explanation") or "").strip()
        if exp:
            parts.append(f"[{sr.get('step')}] {sr.get('assessment', sr.get('answer_status', ''))}: {exp}")
    es = r.get("evidence_summary") or {}
    for key, title in (("malicious_supporting", "Supports malicious"), ("benign_supporting", "Supports benign"), ("unknown", "Unknown")):
        if es.get(key):
            parts.append(f"{title}: " + "; ".join(map(str, es[key])))
    missing = (r.get("telemetry_coverage") or {}).get("missing") or []
    for m in missing:
        parts.append(f"Not examined — {m.get('target')}: {str(m.get('impact', '')).strip()}")

    attrs = [
        a("hypothesis-id", "H1"),
        a("outcome", obj_outcome),
        a("conclusion", "\n".join(parts)),
    ]
    recs = r.get("hunting_recommendations") or []
    if recs:
        attrs.append(a("recommendation", "\n".join(f"- {x}" for x in recs)))
    attrs.append(a("detection-gap", "0", type_="boolean"))
    obj = _object("threat-hunt-finding", ns, f"finding:{r.get('run', '')}", attrs, comment=f"run {r.get('run', '')}")

    tags = [_tag("outcome", hunt_ex_outcome), _tag("content", "finding")]
    byproducts = [str(b) for b in (r.get("byproducts") or []) if str(b) in _HUNT_EX["byproduct"]]
    if missing and "data-source-gap" not in byproducts:
        byproducts.append("data-source-gap")
    tags.extend(_tag("byproduct", b) for b in byproducts)
    if str(r.get("handoff") or "") in _HUNT_EX["handoff"]:
        tags.append(_tag("handoff", str(r["handoff"])))
    return obj, tags


def _event_tags(pb: Playbook, misp: dict, result_tags: list[dict]) -> list[dict]:
    tags: list[dict] = []
    tlp = _tlp(pb.meta)
    if tlp:
        tags.append({"name": f"tlp:{'clear' if tlp == 'white' else tlp}"})
    tags.append(_tag("content", "hypothesis"))
    if _query_steps(pb):
        tags.append(_tag("content", "query"))
    classification = _classification(pb)
    tags.append(_tag("methodology", classification.get("methodology") or "structured-hypothesis-driven"))
    for pred in ("trigger", "applicability", "handoff"):
        vals = classification.get(pred)
        for v in [vals] if isinstance(vals, str) else (vals or []):
            tags.append(_tag(pred, str(v)))
    for tele in _telemetry(pb):
        tags.append(_tag("telemetry", tele))
    seen_langs: list[str] = []
    for s in _query_steps(pb):
        ql = _LANG_TO_HUNT_EX.get((s.lang or "").lower(), "other")
        if ql not in seen_langs:
            seen_langs.append(ql)
            tags.append(_tag("query-language", ql))
    tags.extend(result_tags)
    for extra in misp.get("tags") or []:
        tags.append({"name": str(extra)})
    # de-dup, keep order
    out, seen = [], set()
    for t in tags:
        if t["name"] not in seen:
            seen.add(t["name"])
            out.append(t)
    return out


def playbook_to_misp(
    pb: Playbook,
    *,
    source: str | None = None,
    result: dict | None = None,
    date: str | None = None,
) -> dict[str, Any]:
    """Compile the IR (and optionally its run result) into a MISP event.

    ``source`` is the original hunt.md text; when given it is attached verbatim so
    that :func:`misp_to_markdown` is exact. Without it the export is objects-only
    (still valid, still searchable — but the control flow is summarised, not
    carried).
    """
    ns = _playbook_uuid(pb)
    misp = _misp_block(pb)
    if source is None:
        source = playbook_to_markdown(pb)

    context = _context_object(pb, ns, misp, result)
    hypothesis = _hypothesis_object(pb, ns, misp, result)
    _reference(hypothesis, ns, "part-of", context["uuid"])
    objects = [context, hypothesis]
    for s in _query_steps(pb):
        q = _query_object(pb, ns, s)
        _reference(q, ns, "tests", hypothesis["uuid"], comment="query tests hypothesis H1")
        objects.append(q)

    result_tags: list[dict] = []
    if result:
        finding, result_tags = _finding_object(pb, ns, result)
        _reference(finding, ns, "concludes", hypothesis["uuid"], comment="finding concludes hypothesis H1")
        objects.append(finding)

    slug = _slug(pb)
    attachment = _attr(
        None,
        f"{slug}.hunt.md",
        type_="attachment",
        uid=_uid(ns, "attr", "source"),
        comment=SOURCE_ATTACHMENT_COMMENT,
        data=base64.b64encode(source.encode("utf-8")).decode("ascii"),
    )
    attachment.pop("object_relation")

    tlp = _tlp(pb.meta) or "amber"
    distribution = misp.get("distribution")
    if distribution is None:
        distribution = {"clear": 3, "white": 3, "green": 2, "amber": 1, "amber+strict": 0, "red": 0}.get(tlp, 0)
    threat = {"critical": 1, "high": 1, "medium": 2, "low": 3}.get(str(pb.meta.get("severity") or "").lower(), 4)

    event: dict[str, Any] = {
        "uuid": str(ns),
        "info": pb.name or "Untitled hunt",
        "date": date or _now().date().isoformat(),
        "distribution": str(distribution),
        "threat_level_id": str(threat),
        "analysis": "2" if result else "0",
        "published": False,
        "Tag": _event_tags(pb, misp, result_tags),
        "Attribute": [attachment],
        "Object": objects,
    }
    for ref in pb.meta.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            event["Attribute"].append(
                _attr(None, ref["url"], type_="link", uid=_uid(ns, "attr", "ref", str(ref["url"])), comment=str(ref.get("name") or ""))
                | {"category": "External analysis"}
            )
            event["Attribute"][-1].pop("object_relation")
    return {"Event": event}


def _slug(pb: Playbook) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (pb.name or "hunt").lower()).strip("-") or "hunt"


def markdown_to_misp(text: str, *, result: dict | None = None, date: str | None = None) -> dict[str, Any]:
    return playbook_to_misp(parse_markdown(text), source=text, result=result, date=date)


# --- import: MISP event → hunt.md -------------------------------------------------


def is_misp_event(defn: Any) -> bool:
    """A MISP event: ``{"Event": {...}}`` or a bare event with ``Object``/``Attribute`` and ``info``."""
    ev = _find_event(defn)
    return ev is not None


def _find_event(defn: Any) -> dict[str, Any] | None:
    if not isinstance(defn, dict):
        return None
    if isinstance(defn.get("Event"), dict):
        return defn["Event"]
    if isinstance(defn.get("response"), list) and defn["response"] and isinstance(defn["response"][0], dict):
        return _find_event(defn["response"][0])
    if "info" in defn and ("Object" in defn or "Attribute" in defn):
        return defn
    return None


def _obj_attrs(obj: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in obj.get("Attribute") or []:
        rel = a.get("object_relation")
        if rel:
            out.setdefault(rel, []).append(str(a.get("value", "")))
    return out


def _first(attrs: dict[str, list[str]], key: str) -> str | None:
    vals = attrs.get(key)
    return vals[0] if vals else None


def misp_to_source(defn: Any) -> str | None:
    """The exact hunt.md source if the event carries the attachment; else None."""
    ev = _find_event(defn)
    if not ev:
        return None
    for a in ev.get("Attribute") or []:
        if a.get("type") == "attachment" and str(a.get("value", "")).endswith(".hunt.md") and a.get("data"):
            try:
                return base64.b64decode(a["data"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
    return None


def misp_to_playbook(defn: Any) -> Playbook:
    """Reconstruct a Playbook from a MISP event.

    Prefers the attached source (exact). Otherwise builds a draft from the
    threat-hunt-* objects (plus any linked ``sigma``/``yara`` objects): one query
    step per query object, hypothesis/labels/targets from context + hypothesis,
    and TODO markers where the event has no answer.
    """
    ev = _find_event(defn)
    if ev is None:
        raise ConversionError("not a MISP event (expected {'Event': {...}} or an object with 'info' + 'Object')")
    source = misp_to_source(defn)
    if source is not None:
        return parse_markdown(source)

    objs = ev.get("Object") or []
    by_name: dict[str, list[dict]] = {}
    for o in objs:
        by_name.setdefault(str(o.get("name")), []).append(o)
    tags = [str(t.get("name", "")) for t in ev.get("Tag") or []]

    context = _obj_attrs(by_name.get("threat-hunt-context", [{}])[0])
    hyps = [_obj_attrs(o) for o in by_name.get("threat-hunt-hypothesis", [])]
    hyp = hyps[0] if hyps else {}

    pb = Playbook()
    pb.name = _first(context, "hunt-title") or str(ev.get("info") or "Imported hunt")
    meta: dict[str, Any] = {"type": "investigation", "name": pb.name}

    labels = ["hunt"]
    for h in hyps:
        for tid in h.get("attack-id") or []:
            for m in re.finditer(r"T\d{4}(?:\.\d{3})?", tid, re.I):
                lab = f"attack.{m.group(0).lower()}"
                if lab not in labels:
                    labels.append(lab)
    if len(labels) == 1:
        labels.append("attack.tXXXX  # TODO: technique")
    meta["labels"] = labels

    tlp = next((m.group(1).lower() for t in tags for m in [_TLP_TAG.match(t)] if m), None)
    meta["tlp"] = "clear" if tlp == "white" else (tlp or "amber")
    threat = str(ev.get("threat_level_id") or "")
    meta["severity"] = {"1": "high", "2": "medium", "3": "low"}.get(threat, "medium")

    hypothesis_text = _first(hyp, "hypothesis")
    if len(hyps) > 1:
        hypothesis_text = (hypothesis_text or "") + "\n\nTODO: this event carried " + str(len(hyps)) + " hypotheses; hunt.md is one hypothesis per file — split the others: " + " | ".join(
            (_first(h, "hypothesis-id") or "?") + ": " + (_first(h, "hypothesis") or "")[:80] for h in hyps[1:]
        )
    meta["hypothesis"] = hypothesis_text or "TODO: state the hypothesis (event had no threat-hunt-hypothesis object)"

    refs = []
    for a in ev.get("Attribute") or []:
        if a.get("type") == "link" and a.get("value"):
            refs.append({"name": str(a.get("comment") or a["value"]), "url": str(a["value"])})
    if refs:
        meta["references"] = refs

    # Targets: one per distinct data-source across query objects (falling back to context data-sources).
    targets: dict[str, dict[str, Any]] = {}
    ds_slug: dict[str, str] = {}

    def target_for(name: str | None, platform: str | None) -> str:
        key = name or platform or "source"
        if key in ds_slug:
            return ds_slug[key]
        slug = re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-") or f"source-{len(targets) + 1}"
        base, n = slug, 2
        while slug in targets:
            slug, n = f"{base}-{n}", n + 1
        t: dict[str, Any] = {"category": "siem", "name": key}  # category is a guess — flagged in the TODO
        targets[slug] = t
        ds_slug[key] = slug
        return slug

    steps: list[Step] = []
    used: set[str] = set()

    def add_query(slug_hint: str, lang: str, body: str, target: str, desc: str | None) -> None:
        slug = re.sub(r"[^a-z0-9]+", "-", slug_hint.lower()).strip("-") or "query"
        base, n = slug, 2
        while slug in used:
            slug, n = f"{base}-{n}", n + 1
        used.add(slug)
        s = Step(slug=slug, kind="query", lang=lang, target=target, body=body.rstrip("\n") + "\n")
        if desc:
            s.attrs["description"] = desc
        steps.append(s)

    for i, o in enumerate(by_name.get("threat-hunt-query", []), 1):
        a = _obj_attrs(o)
        ql = (_first(a, "query-language") or "other").strip().lower()
        lang = _HUNT_EX_TO_LANG.get(ql, re.sub(r"[^a-z0-9-]", "", ql) or "text")
        hint = str(o.get("comment") or "").removeprefix("hunt.md step").strip(" `:") or f"query-{i}"
        add_query(hint, lang, _first(a, "query") or "TODO: query text", target_for(_first(a, "data-source"), _first(a, "platform")), _first(a, "comment"))
    for o in by_name.get("sigma", []):
        a = _obj_attrs(o)
        add_query(_first(a, "sigma-rule-name") or "sigma-rule", "sigma", _first(a, "sigma") or "", target_for("SIEM", None), _first(a, "context"))
    for o in by_name.get("yara", []):
        a = _obj_attrs(o)
        add_query(_first(a, "yara-rule-name") or "yara-rule", "yara", _first(a, "yara") or "", target_for("Endpoint", None), _first(a, "context"))

    if not steps:
        for ds in context.get("data-source") or ["source"]:
            target_for(ds, None)
        first = next(iter(targets))
        add_query("collect", "kql", "// TODO: the event carried no threat-hunt-query object — write the query", first, None)

    # Findings become a manual review step: the imported evidence a re-run should be compared against.
    findings = [_obj_attrs(o) for o in by_name.get("threat-hunt-finding", [])]
    if findings:
        f = findings[0]
        body = f"Prior finding ({_first(f, 'outcome') or '?'}): {_first(f, 'conclusion') or ''}".strip()
        if _first(f, "recommendation"):
            body += f"\n\nRecommendation: {_first(f, 'recommendation')}"
        targets.setdefault("analyst", {"role": "analyst", "name": "Analyst"})
        steps.append(Step(slug="compare-with-prior-finding", kind="task", target="analyst", body=body + "\n"))

    classification: dict[str, Any] = {}
    planes: list[str] = []
    for t in tags:
        m = _HUNT_EX_TAG.match(t)
        if m and m.group(1) in ("methodology", "trigger", "applicability", "handoff"):
            classification.setdefault(m.group(1), []).append(m.group(2))
        elif m and m.group(1) == "telemetry":
            planes.append(m.group(2))
    if _first(context, "methodology"):
        classification["methodology"] = _first(context, "methodology")
    for k, v in list(classification.items()):
        if isinstance(v, list) and len(v) == 1:
            classification[k] = v[0]
    if classification:
        meta["hunt"] = classification
    # The event's telemetry planes land on the (guessed) targets, where SPEC §6 keeps them.
    if planes:
        for t in targets.values():
            if not (t.get("agent") or t.get("role") or t.get("individual")):
                t["telemetry"] = planes if len(planes) > 1 else planes[0]
    meta["targets"] = targets
    meta["misp"] = {"event": str(ev.get("uuid") or "")}

    pb.meta = meta
    pb.steps = steps
    purpose = _first(context, "purpose")
    analysis = _first(hyp, "analysis")
    desc = [p for p in (purpose, analysis) if p]
    desc.append(
        "TODO: imported from a MISP event — the objects carry queries and the hypothesis, not control flow. "
        "Add decisions/agent steps, and check each target's `category:` (guessed as siem)."
    )
    pb.description = "\n\n".join(desc)
    from huntmd.core import Edge  # noqa: PLC0415 - local to keep the top import list honest

    for a_, b_ in zip(steps, steps[1:]):
        pb.edges.append(Edge(a_.slug, b_.slug))
    return pb


def misp_to_markdown(defn: Any) -> str:
    source = misp_to_source(defn)
    if source is not None:
        return source
    return playbook_to_markdown(misp_to_playbook(defn))


# --- lint (profile: misp) ---------------------------------------------------------


def misp_issues(pb: Playbook) -> list[tuple[str, str, str]]:
    """(level, slug, message) tuples for ``validate --profile misp``."""
    out: list[tuple[str, str, str]] = []
    misp = _misp_block(pb)
    for pred in ("methodology", "trigger", "applicability", "handoff", "telemetry"):
        vals = misp.get(pred)
        if vals is None:
            continue
        moved = f"hunt.{pred}" if pred != "telemetry" else "targets.<slug>.telemetry"
        out.append(("info", "", f"misp.{pred} moved to {moved} in 0.6 — still honoured; move it when convenient"))
        for v in [vals] if isinstance(vals, str) else (vals or []):
            if str(v) not in _HUNT_EX[pred]:
                out.append(("warn", "", f"misp.{pred} '{v}' not in hunt-ex vocabulary {list(_HUNT_EX[pred])}"))
    for s in _query_steps(pb):
        if (s.lang or "").lower() not in _LANG_TO_HUNT_EX:
            out.append(("warn", s.slug, f"query language '{s.lang}' has no hunt-ex:query-language mapping — will export as 'other'"))
    if not _telemetry(pb):
        out.append(("warn", "", "no target category maps to a hunt-ex:telemetry value — peers can't filter this hunt by telemetry"))
    if not _attack_ids(pb.meta):
        out.append(("warn", "", "no attack.tXXXX label — threat-hunt-hypothesis.attack-id will be empty"))
    return out
