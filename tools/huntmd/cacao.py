"""hunt.md IR → OASIS CACAO Security Playbooks v2 (JSON) export.

Implements the CACAO profile described in ``../PROFILES.md`` §2. CACAO is the
interchange target: this compiles the parsed hunt graph into a complete CACAO
v2.0 playbook for STIX/TAXII sharing and SOAR consumption. The ``.md`` stays the
source of truth — export is one-way.

Hunt-specific semantics (queries, agent directives, fuzzy conditions, hunt
metadata) travel as CACAO *extensions*, which is the mechanism CACAO defines for
domain-specific content. A generic CACAO consumer runs the workflow skeleton; a
hunt-aware one additionally reads the hypothesis, ATT&CK coverage and agent
directives out of the extension payloads.

Identifiers are deterministic (``uuid5`` over the playbook id + ``kind:slug``,
per SPEC §10), so re-exporting an unchanged hunt yields a byte-identical
artifact apart from the ``modified`` timestamp.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from huntmd.core import ConversionError, Edge, Playbook, Step, effective_guardrails, parse_markdown

CACAO_SPEC_VERSION = "cacao-2.0"

#: Stable namespace for all hunt.md-derived CACAO identifiers.
_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "hunt.md")

#: IR kind -> CACAO workflow step type. Decisions split on `switch_cases`.
_STEP_TYPE = {
    "query": "action",
    "collection": "action",
    "agent": "action",
    "task": "action",
    "action": "action",
    "decision": "if-condition",
    "loop": "while-condition",
    "subplaybook": "playbook-action",
    "parallel": "parallel",
}

#: Ordinal severity -> CACAO's 0-100 scale (inverse of SPEC §3.2 bucketing).
_SEVERITY_NUMERIC = {"critical": 90, "high": 70, "medium": 40, "low": 10}

_ATTACK = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)
_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")

#: Extension definitions emitted alongside whatever the hunt actually uses.
_EXTENSIONS = {
    "x-org-query": "Query command: carries a query language, query text and bound parameters.",
    "x-org-agent-directive": "Agent directive: an objective, tool allowlist and iteration bound for a reasoning agent.",
    "x-org-ai-agent": "AI agent definition: a reasoning agent the executing runtime binds at run time.",
    "x-org-fuzzy-condition": "Fuzzy condition: an agent-judged predicate with a confidence threshold and an indeterminate branch.",
    "x-hunt": "Hunt metadata: hypothesis, ATT&CK techniques and data requirements for a threat-hunting playbook.",
}


# --- identifiers ------------------------------------------------------------


def _playbook_uuid(pb: Playbook) -> uuid.UUID:
    """Stable playbook UUID: frontmatter ``id`` if pinned, else derived from the name."""
    pinned = pb.meta.get("id")
    if pinned:
        raw = str(pinned).split("--")[-1]
        try:
            return uuid.UUID(raw)
        except ValueError:
            return uuid.uuid5(_NS, str(pinned))
    return uuid.uuid5(_NS, pb.name or "untitled-hunt")


def _oid(pb_uuid: uuid.UUID, cacao_type: str, kind: str, slug: str) -> str:
    """``<cacao-type>--uuid5(playbook, "<kind>:<slug>")`` — SPEC §10 identity."""
    return f"{cacao_type}--{uuid.uuid5(pb_uuid, f'{kind}:{slug}')}"


# --- helpers ----------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _var(name: str) -> str:
    """hunt.md ``{{param}}`` / ``$var`` -> CACAO's ``__name__`` variable form."""
    return f"__{name.lstrip('$')}__"


def _to_cacao_placeholders(body: str, params: dict[str, str]) -> str:
    """Rewrite ``{{qname}}`` to the bound CACAO variable ``__source__``.

    ``params=(days=lookback)`` + ``{{days}}`` -> ``__lookback__``; an unbound
    placeholder keeps its own name (``{{x}}`` -> ``__x__``) so nothing is left
    dangling in the exported command.
    """
    return _PLACEHOLDER.sub(lambda m: _var(params.get(m.group(1), m.group(1))), body)


def _severity(meta: dict[str, Any]) -> int | None:
    sev = meta.get("severity")
    if isinstance(sev, bool):
        return None
    if isinstance(sev, (int, float)):
        return max(0, min(100, int(sev)))
    if isinstance(sev, str):
        return _SEVERITY_NUMERIC.get(sev.strip().lower())
    return None


def _attack_techniques(meta: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for label in meta.get("labels") or []:
        m = _ATTACK.match(str(label).strip())
        if m:
            out.append(f"{m.group(1).upper()}.{m.group(2)}" if m.group(2) else m.group(1).upper())
    return out


def _plain_labels(meta: dict[str, Any]) -> list[str]:
    return [str(x) for x in (meta.get("labels") or []) if not _ATTACK.match(str(x).strip())]


def _external_references(meta: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for ref in meta.get("references") or []:
        if isinstance(ref, dict):
            entry = {"name": ref.get("name") or ref.get("url") or "reference"}
            if ref.get("url"):
                entry["url"] = ref["url"]
            if ref.get("description"):
                entry["description"] = ref["description"]
            refs.append(entry)
        elif ref:
            refs.append({"name": str(ref)})
    for tech in _attack_techniques(meta):
        path = tech.replace(".", "/")
        refs.append(
            {
                "name": f"MITRE ATT&CK {tech}",
                "source_name": "mitre-attack",
                "external_id": tech,
                "url": f"https://attack.mitre.org/techniques/{path}/",
            }
        )
    return refs


def _determinism(pb: Playbook) -> str:
    """SPEC §10 determinism label — compiler-emitted, author-immutable."""
    for s in pb.steps:
        if s.kind in ("agent", "task") or (s.kind == "decision" and s.fuzzy):
            return "hybrid"
    return "deterministic"


# --- agents, targets, variables ---------------------------------------------


def _definitions(pb: Playbook, pb_uuid: uuid.UUID) -> tuple[dict, dict, dict[str, str]]:
    """frontmatter ``targets:`` -> (agent_definitions, target_definitions, slug->id)."""
    agents: dict[str, Any] = {}
    targets: dict[str, Any] = {}
    ids: dict[str, str] = {}

    for slug, spec in (pb.meta.get("targets") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        name = spec.get("name") or slug
        # `x_hunt_slug` (and `x_hunt_role`) let an import recover the author's own
        # slug rather than re-deriving one from the display name.
        if spec.get("agent"):
            oid = _oid(pb_uuid, "x-org-ai-agent", "agent", slug)
            entry: dict[str, Any] = {"type": "x-org-ai-agent", "name": name, "x_hunt_slug": slug}
            if spec.get("model"):
                entry["model_hint"] = spec["model"]  # non-binding (SPEC §6)
            agents[oid] = entry
        elif spec.get("individual"):
            oid = _oid(pb_uuid, "individual", "target", slug)
            targets[oid] = {"type": "individual", "name": str(spec["individual"]), "x_hunt_slug": slug}
        elif spec.get("role"):
            oid = _oid(pb_uuid, "group", "target", slug)
            targets[oid] = {
                "type": "group",
                "name": name,
                "description": f"role: {spec['role']}",
                "x_hunt_slug": slug,
                "x_hunt_role": spec["role"],
            }
        else:
            oid = _oid(pb_uuid, "security-infrastructure-category", "target", slug)
            entry = {"type": "security-infrastructure-category", "name": name, "x_hunt_slug": slug}
            if spec.get("category"):
                entry["category"] = [str(spec["category"])]
            # Per-runtime binding hints stay namespaced rather than being flattened.
            bindings = {k: v for k, v in spec.items() if isinstance(v, dict)}
            if bindings:
                entry["x_hunt_bindings"] = bindings
            targets[oid] = entry
        ids[slug] = oid
    return agents, targets, ids


def _playbook_variables(pb: Playbook) -> dict[str, Any]:
    """``parameters:`` -> external variables; ``$var`` dataflow -> internal ones."""
    variables: dict[str, Any] = {}
    for name, spec in (pb.meta.get("parameters") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        entry: dict[str, Any] = {
            "type": _cacao_var_type(spec.get("type")),
            "external": True,  # collected at launch (SPEC §3.1)
            "constant": False,
        }
        if spec.get("description"):
            entry["description"] = spec["description"]
        if spec.get("type") and _cacao_var_type(spec["type"]) != str(spec["type"]).lower():
            entry["x_hunt_type"] = str(spec["type"])  # e.g. `duration`, which CACAO has no type for
        if spec.get("default") is not None:
            entry["value"] = str(spec["default"])
        variables[_var(name)] = entry

    for s in pb.steps:
        for produced in _declared_vars(s, "out"):
            variables.setdefault(
                _var(produced),
                {
                    "type": "string",
                    "description": f"runtime output of step '{s.slug}'",
                    "external": False,
                    "constant": False,
                },
            )
    return variables


def _cacao_var_type(t: Any) -> str:
    """hunt.md parameter type -> CACAO variable type (unknown types degrade to string)."""
    known = {
        "string": "string",
        "number": "long",
        "integer": "long",
        "boolean": "string",
        "ip": "ipv4-addr",
        "ipv4": "ipv4-addr",
        "ipv6": "ipv6-addr",
        "host": "hostname",
        "hostname": "hostname",
        "uri": "uri",
        "url": "uri",
        "date": "string",
        "duration": "string",
        "query": "string",
    }
    return known.get(str(t).strip().lower(), "string")


def _declared_vars(s: Step, key: str) -> list[str]:
    value = s.attrs.get(key)
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    if not isinstance(value, list):
        return []
    return [str(v).lstrip("$") for v in value if str(v).startswith("$")]


# --- workflow ---------------------------------------------------------------


def _commands(s: Step, params_as_vars: dict[str, str]) -> list[dict[str, Any]]:
    if s.kind in ("query", "collection"):
        cmd: dict[str, Any] = {
            "type": "x-org-query",
            "query_language": s.lang or "unknown",
            "content": _to_cacao_placeholders(s.body.strip(), s.params),
        }
        if s.kind == "collection":
            cmd["collection"] = True
        if params_as_vars:
            cmd["parameters"] = params_as_vars
        return [cmd]
    if s.kind == "agent":
        cmd = {
            "type": "x-org-agent-directive",
            "objective": str(s.attrs.get("objective", s.body)).strip(),
        }
        for key, out_key in (
            ("tools", "tools"),
            ("success_criteria", "success_criteria"),
            ("max_iterations", "max_iterations"),
            ("context", "context"),
        ):
            if key in s.attrs:
                cmd[out_key] = s.attrs[key]
        return [cmd]
    if s.kind == "task":
        return [{"type": "manual", "command": s.body.strip()}]
    # action
    return [{"type": "manual", "command": s.body.strip()}]


def _workflow(pb: Playbook, pb_uuid: uuid.UUID, target_ids: dict[str, str]) -> tuple[dict, str]:
    """Build the CACAO workflow map. Returns (workflow, workflow_start id)."""
    executable = [s for s in pb.steps if s.kind in _STEP_TYPE]
    by_slug = {s.slug: s for s in executable}

    def type_of(s: Step) -> str:
        if s.kind == "decision" and s.switch_cases:
            return "switch-condition"
        return _STEP_TYPE[s.kind]

    step_ids = {s.slug: _oid(pb_uuid, type_of(s), s.kind, s.slug) for s in executable}
    start_id = _oid(pb_uuid, "start", "control", "start")
    end_id = _oid(pb_uuid, "end", "control", "end")

    children: dict[str, list[tuple[str, str | None]]] = {}
    for e in pb.edges:
        if e.frm in step_ids and e.to in step_ids:
            children.setdefault(e.frm, []).append((e.to, e.branch))

    def resolve(slug: str) -> list[str]:
        return [step_ids[slug]] if slug in step_ids else [end_id]

    def branch_of(slug: str, wanted: str) -> list[str]:
        return [step_ids[t] for t, b in children.get(slug, []) if b == wanted]

    def unbranched(slug: str) -> list[str]:
        return [step_ids[t] for t, b in children.get(slug, []) if b is None]

    workflow: dict[str, Any] = {}
    roots = [s for s in executable if not any(e.to == s.slug for e in pb.edges)]
    first = step_ids[roots[0].slug] if roots else (step_ids[executable[0].slug] if executable else end_id)
    workflow[start_id] = {"type": "start", "name": "Start", "on_completion": first}

    for s in executable:
        sid = step_ids[s.slug]
        ctype = type_of(s)
        step: dict[str, Any] = {"type": ctype, "name": s.label or s.slug}
        # The authored slug (which may carry a `###` group path) can't be
        # recovered from the display name alone, so carry it for the importer.
        step["x_hunt_slug"] = s.slug
        if s.attrs.get("description"):
            step["description"] = str(s.attrs["description"])
        kids = children.get(s.slug, [])

        if ctype == "action":
            params_as_vars = {q: _var(src) for q, src in (s.params or {}).items()}
            step["commands"] = _commands(s, params_as_vars)
            if s.target and s.target in target_ids:
                # `agent` is who performs the step (a reasoning agent, or the
                # role a manual task is assigned to); `targets` is what it acts on.
                if s.kind in ("agent", "task"):
                    step["agent"] = target_ids[s.target]
                else:
                    step["targets"] = [target_ids[s.target]]
            if s.kind == "agent":
                for key in ("in", "out"):
                    declared = _declared_vars(s, key)
                    if declared:
                        step.setdefault("step_variables", {}).update(
                            {_var(v): {"type": "string", "external": False, "constant": False} for v in declared}
                        )
            # CACAO renders both a human task and a change/response as a `manual`
            # command, so the IR kind is carried explicitly — otherwise a
            # round-trip silently downgrades an `action` into a `task`.
            step["x_hunt_kind"] = s.kind
            if s.kind == "action" and s.attrs.get("approval"):
                # No native CACAO gate; carried so a hunt-aware consumer still enforces it.
                step["x_hunt_approval"] = str(s.attrs["approval"])
            nxt = unbranched(s.slug) or [step_ids[t] for t, _ in kids]
            if len(nxt) > 1:  # fan-out from a non-decision step needs an explicit parallel
                pid, pstep = _synthetic_parallel(pb_uuid, s.slug, nxt)
                workflow[pid] = pstep
                step["on_completion"] = pid
            else:
                step["on_completion"] = nxt[0] if nxt else end_id

        elif ctype == "if-condition":
            step["condition"] = s.condition or ""
            # `then:`/`else:` pointing at `end` leave no edge in the IR (end is
            # implicit, SPEC §4.1) — CACAO wants both arms explicit, so an
            # absent branch resolves to the end step rather than dangling.
            step["on_true"] = branch_of(s.slug, "on_supports") or unbranched(s.slug) or [end_id]
            step["on_false"] = branch_of(s.slug, "on_refutes") or [end_id]
            if s.fuzzy:
                fuzzy: dict[str, Any] = {"predicate": s.condition or ""}
                if s.confidence is not None:
                    # Ordinal is the format's preferred form (SPEC §7.2); a
                    # numeric threshold is carried verbatim so it round-trips.
                    if isinstance(s.confidence, (int, float)):
                        fuzzy["confidence_threshold"] = s.confidence
                    else:
                        fuzzy["confidence"] = s.confidence
                if s.judge and s.judge in target_ids:
                    fuzzy["judge"] = target_ids[s.judge]
                elif s.judge:
                    fuzzy["judge"] = s.judge
                indeterminate = branch_of(s.slug, "default")
                if indeterminate:
                    fuzzy["on_indeterminate"] = indeterminate
                unavailable = branch_of(s.slug, "on_unavailable")
                if unavailable:
                    fuzzy["on_unavailable"] = unavailable
                if s.unavailable_to_end:
                    fuzzy["on_unavailable"] = [end_id]
                step["x_org_fuzzy_condition"] = fuzzy

        elif ctype == "switch-condition":
            step["switch"] = s.condition or ""
            cases: dict[str, list[str]] = {}
            for value, target in s.switch_cases:
                cases[str(value)] = resolve(target)
            step["cases"] = cases

        elif ctype == "while-condition":
            step["condition"] = s.condition or ""
            body = unbranched(s.slug)
            if body:
                step["on_true"] = body
            step["on_completion"] = end_id

        elif ctype == "playbook-action":
            step["playbook_id"] = s.run_target or ""
            nxt = unbranched(s.slug)
            step["on_completion"] = nxt[0] if nxt else end_id

        elif ctype == "parallel":
            step["next_steps"] = [step_ids[b] for b in s.branches if b in step_ids]
            if s.join and s.join in step_ids:
                step["on_completion"] = step_ids[s.join]
            else:
                step["on_completion"] = end_id

        workflow[sid] = step

    workflow[end_id] = {"type": "end", "name": "End"}
    return workflow, start_id


def _synthetic_parallel(pb_uuid: uuid.UUID, slug: str, next_ids: list[str]) -> tuple[str, dict[str, Any]]:
    """CACAO action steps have a single `on_completion`; fan-out becomes a parallel step."""
    pid = _oid(pb_uuid, "parallel", "control", f"fanout:{slug}")
    return pid, {"type": "parallel", "name": f"fan-out from {slug}", "next_steps": next_ids}


# --- entry points -----------------------------------------------------------


def playbook_to_cacao(pb: Playbook, *, created: str | None = None) -> dict[str, Any]:
    """Compile the hunt.md IR into a CACAO v2.0 playbook object."""
    if not pb.steps:
        raise ConversionError("Hunt has no steps to export.")
    pb_uuid = _playbook_uuid(pb)
    stamp = created or str(pb.meta.get("created") or "") or _now()
    agents, targets, target_ids = _definitions(pb, pb_uuid)
    workflow, start_id = _workflow(pb, pb_uuid, target_ids)

    data_requirements = sorted(
        {s.target for s in pb.steps if s.kind in ("query", "collection") and s.target}
    )
    hypothesis = pb.meta.get("hypothesis")

    playbook: dict[str, Any] = {
        "type": "playbook",
        "spec_version": CACAO_SPEC_VERSION,
        "id": f"playbook--{pb_uuid}",
        "name": pb.name,
        "playbook_types": ["investigation"],
        "created_by": f"identity--{uuid.uuid5(_NS, str(pb.meta.get('created_by') or 'hunt.md'))}",
        "created": stamp,
        "modified": str(pb.meta.get("modified") or "") or stamp,
        "revoked": False,
        "playbook_processing_summary": {
            "manual_playbook": _determinism(pb) == "hybrid",
            "parallel_processing": any(s.kind == "parallel" for s in pb.steps),
        },
        "workflow_start": start_id,
        "workflow": workflow,
    }
    if pb.description or hypothesis:
        playbook["description"] = (pb.description or str(hypothesis)).strip()
    labels = _plain_labels(pb.meta)
    if labels:
        playbook["labels"] = labels
    refs = _external_references(pb.meta)
    if refs:
        playbook["external_references"] = refs
    severity = _severity(pb.meta)
    if severity is not None:
        playbook["severity"] = severity
    if pb.meta.get("tlp"):
        playbook["markings"] = [f"marking-tlp--{str(pb.meta['tlp']).lower()}"]
    variables = _playbook_variables(pb)
    if variables:
        playbook["playbook_variables"] = variables
    if agents:
        playbook["agent_definitions"] = agents
    if targets:
        playbook["target_definitions"] = targets

    # x-hunt: what makes a CACAO library queryable as a *hunt* catalog (PROFILES §2).
    # Guardrails travel with the playbook: a consumer that executes agent steps
    # needs the safety posture, not just the workflow (SPEC §8.1).
    x_hunt: dict[str, Any] = {"determinism": _determinism(pb), "guardrails": effective_guardrails(pb.meta)}
    if hypothesis:
        x_hunt["hypothesis"] = str(hypothesis).strip()
    if _attack_techniques(pb.meta):
        x_hunt["attack_techniques"] = _attack_techniques(pb.meta)
    if data_requirements:
        x_hunt["data_requirements"] = data_requirements
    if pb.meta.get("type"):
        x_hunt["hunt_type"] = pb.meta["type"]
    playbook["x_hunt"] = x_hunt

    playbook["extension_definitions"] = {
        _oid(pb_uuid, "extension-definition", "extension", name): {
            "type": "extension-definition",
            "name": name,
            "description": description,
            "created_by": playbook["created_by"],
            "schema": f"https://huntbase.io/schemas/hunt-md/{name}.json",
            "version": "1.0.0",
        }
        for name, description in _EXTENSIONS.items()
    }
    return playbook


def markdown_to_cacao(text: str, *, created: str | None = None) -> dict[str, Any]:
    """hunt.md source -> CACAO v2.0 playbook object."""
    return playbook_to_cacao(parse_markdown(text), created=created)


# --- import: CACAO -> hunt.md -----------------------------------------------
#
# Inbound is best-effort by nature: a foreign playbook carries no hypothesis, no
# ATT&CK labels and no abstract targets, and its step kinds are only recoverable
# from command types. The importer produces a *draft* — it marks what a human
# has to supply with `TODO`, so `huntmd validate` immediately points at the gaps.
# Tested against ~50 real playbooks from six independent projects; the leniency
# below (CACAO 1.1 `single` steps, `step--slug` ids, three variable-naming
# conventions) is what that corpus actually contains.

#: CACAO step type -> IR kind. `single` is CACAO 1.x's action step.
_CACAO_STEP_KIND = {
    "action": "action",
    "single": "action",
    "if-condition": "decision",
    "switch-condition": "decision",
    "while-condition": "loop",
    "loop": "loop",
    "decision": "decision",
    "parallel": "parallel",
    "playbook-action": "subplaybook",
}

#: Command type -> IR kind. Anything else is a change/response (SPEC §9).
_COMMAND_KIND = {
    "x-org-query": "query",
    "x-org-agent-directive": "agent",
    "manual": "task",
}

#: `__x__`, `$$x$$` and bare names all appear in the wild; normalise to `x`.
_VAR_REF = re.compile(r"\$\$([A-Za-z0-9_.-]+)\$\$|__([A-Za-z0-9_.-]+)__")

#: `T1566.001` / `techniques/T1566/001` inside a reference name or URL.
_TECHNIQUE_IN_TEXT = re.compile(r"\b(T\d{4})[./]?(\d{3})?\b", re.I)


def _clean_var(name: str) -> str:
    return name.strip().strip("$").strip("_").replace(".", "_").replace("-", "_")


def _slugify(text: str, taken: set[str]) -> str:
    """Kebab-case a step name into a stable slug, de-duped (SPEC §10)."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(text or "step").lower()).strip("-") or "step"
    candidate, n = slug, 2
    while candidate in taken:
        candidate, n = f"{slug}-{n}", n + 1
    taken.add(candidate)
    return candidate


def _to_placeholders(text: str, known: set[str]) -> str:
    """Rewrite CACAO variable references to portable ``{{name}}`` placeholders."""

    def sub(m: re.Match) -> str:
        name = _clean_var(m.group(1) or m.group(2) or "")
        return "{{" + name + "}}" if name in known else m.group(0)

    return _VAR_REF.sub(sub, text or "")


def _ordinal_severity(value: Any) -> str | None:
    """CACAO's 0-100 severity -> hunt.md's ordinal words (SPEC §3.2 bucketing)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return str(value).lower() if isinstance(value, str) and value else None
    if n >= 80:
        return "critical"
    if n >= 50:
        return "high"
    if n >= 20:
        return "medium"
    return "low"


def _find_playbook(defn: Any) -> dict[str, Any]:
    """Accept a bare playbook or a single-key wrapper ({"<id>": {...}})."""
    if isinstance(defn, dict):
        if isinstance(defn.get("workflow"), dict):
            return defn
        for value in defn.values():
            if isinstance(value, dict) and isinstance(value.get("workflow"), dict):
                return value
    raise ConversionError("Not a CACAO playbook (no 'workflow' object found).")


def _role_from_description(description: Any) -> str | None:
    m = re.match(r"role:\s*(\S+)", str(description or "").strip())
    return m.group(1) if m else None


def _import_definitions(pb_defn: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """agent_definitions/target_definitions -> frontmatter `targets:` + id->slug."""
    targets: dict[str, Any] = {}
    id_to_slug: dict[str, str] = {}
    taken: set[str] = set()

    for oid, spec in (pb_defn.get("agent_definitions") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        slug = _slugify(spec.get("x_hunt_slug") or spec.get("name") or "agent", taken)
        entry: dict[str, Any] = {"agent": True, "name": spec.get("name") or slug}
        if spec.get("model_hint"):
            entry["model"] = spec["model_hint"]
        targets[slug] = entry
        id_to_slug[oid] = slug

    for oid, spec in (pb_defn.get("target_definitions") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        ttype = str(spec.get("type") or "")
        slug = _slugify(spec.get("x_hunt_slug") or spec.get("name") or ttype or "target", taken)
        if ttype == "individual":
            entry = {"individual": spec.get("name") or slug, "name": spec.get("name") or slug}
        elif ttype in ("group", "organization"):
            role = spec.get("x_hunt_role") or _role_from_description(spec.get("description")) or ttype
            entry = {"role": role, "name": spec.get("name") or slug}
        else:
            category = spec.get("category")
            if isinstance(category, list):
                category = category[0] if category else None
            entry = {"category": category or ttype or "unknown", "name": spec.get("name") or slug}
        if isinstance(spec.get("x_hunt_bindings"), dict):
            entry.update(spec["x_hunt_bindings"])
        targets[slug] = entry
        id_to_slug[oid] = slug

    return targets, id_to_slug


def _import_step(  # noqa: C901 - one dispatch per CACAO step type
    slug: str,
    raw: dict[str, Any],
    *,
    id_to_slug: dict[str, str],
    step_slugs: dict[str, str],
    known_vars: set[str],
) -> Step:
    ctype = str(raw.get("type") or "action")
    kind = _CACAO_STEP_KIND.get(ctype, "action")
    commands = [c for c in (raw.get("commands") or []) if isinstance(c, dict)]
    first = commands[0] if commands else {}
    cmd_type = str(first.get("type") or "")

    if kind == "action" and cmd_type in _COMMAND_KIND:
        kind = _COMMAND_KIND[cmd_type]
    # An `x_hunt_kind` hint (present on anything this tool exported) is
    # authoritative — it distinguishes task/action and query/collection, which
    # CACAO's own command types collapse.
    if str(raw.get("x_hunt_kind")) in ("query", "collection", "agent", "task", "action"):
        kind = str(raw["x_hunt_kind"])

    step = Step(slug=slug, kind=kind, label=str(raw.get("name") or slug))
    step.attrs["cacao_id"] = raw.get("__id__", "")  # pinned original id (SPEC §10)
    if raw.get("description"):
        step.attrs["description"] = str(raw["description"])

    agent_id = raw.get("agent")
    target_ids = [t for t in (raw.get("targets") or []) if isinstance(t, str)]
    if isinstance(agent_id, str) and agent_id in id_to_slug:
        step.target = id_to_slug[agent_id]
    elif target_ids and target_ids[0] in id_to_slug:
        step.target = id_to_slug[target_ids[0]]

    def command_text(c: dict[str, Any]) -> str:
        body = c.get("command") or c.get("content") or ""
        if not body and c.get("command_b64"):
            body = f"(base64 command: {c['command_b64']})"
        return _to_placeholders(str(body), known_vars)

    if kind in ("query", "collection"):
        step.lang = str(first.get("query_language") or "sql")
        step.body = command_text(first)
        params = first.get("parameters")
        if isinstance(params, dict):
            step.params = {k: _clean_var(str(v)) for k, v in params.items()}
    elif kind == "agent":
        step.attrs["objective"] = str(first.get("objective") or "")
        for key in ("tools", "success_criteria", "max_iterations", "context"):
            if key in first:
                step.attrs[key] = first[key]
    elif kind in ("task", "action"):
        # Several commands on one step become one body; the command type is kept
        # so nothing about how it executes is lost (Tier 2).
        # Real playbooks contain command objects with no command text at all;
        # fall back to the step description so the block is never empty.
        step.body = (
            "\n".join(t for t in (command_text(c) for c in commands) if t.strip())
            or str(raw.get("description") or "")
            or "TODO: the source playbook declared no command for this step."
        )
        types = sorted({str(c.get("type")) for c in commands if c.get("type") and c.get("type") != "manual"})
        if types:
            step.attrs["command_type"] = types[0] if len(types) == 1 else types
        if raw.get("x_hunt_approval"):
            step.attrs["approval"] = raw["x_hunt_approval"]
    elif kind == "decision":
        step.condition = str(raw.get("condition") or raw.get("switch") or "")
        fuzzy = raw.get("x_org_fuzzy_condition") or {}
        if isinstance(fuzzy, dict) and fuzzy:
            step.fuzzy = True
            step.condition = str(fuzzy.get("predicate") or step.condition)
            step.confidence = fuzzy.get("confidence") or fuzzy.get("confidence_threshold")
            judge = fuzzy.get("judge")
            step.judge = id_to_slug.get(str(judge), str(judge)) if judge else None
        cases = raw.get("cases")
        if isinstance(cases, dict):
            for value, targets in cases.items():
                for tid in targets if isinstance(targets, list) else [targets]:
                    step.switch_cases.append((str(value), step_slugs.get(str(tid), "end")))
    elif kind == "loop":
        step.condition = f"`{raw.get('condition') or ''}`"
    elif kind == "parallel":
        step.branches = [step_slugs[t] for t in (raw.get("next_steps") or []) if t in step_slugs]
    elif kind == "subplaybook":
        step.run_target = str(raw.get("playbook_id") or "")

    return step


def cacao_to_playbook(defn: Any) -> Playbook:
    """CACAO playbook (v1.1 or v2.0) -> hunt.md IR. Best-effort; see module notes."""
    src = _find_playbook(defn)
    workflow = {k: v for k, v in (src.get("workflow") or {}).items() if isinstance(v, dict)}
    if not workflow:
        raise ConversionError("CACAO playbook has an empty 'workflow'.")

    known_vars = {_clean_var(v) for v in (src.get("playbook_variables") or {})}

    # Slug every non-control step first: edges are rewritten in terms of slugs.
    taken: set[str] = set()
    step_slugs: dict[str, str] = {}
    control: dict[str, str] = {}
    for sid, raw in workflow.items():
        ctype = str(raw.get("type") or "action")
        if ctype in ("start", "end"):
            control[sid] = ctype
            continue
        authored = raw.get("x_hunt_slug")  # round-tripping our own export
        if isinstance(authored, str) and authored and authored not in taken:
            taken.add(authored)
            step_slugs[sid] = authored
        else:
            step_slugs[sid] = _slugify(raw.get("name") or sid.split("--")[0], taken)

    _, id_to_slug = _import_definitions(src)
    pb = Playbook(name=str(src.get("name") or "Imported playbook"))
    for sid, raw in workflow.items():
        if sid in control:
            continue
        pb.steps.append(
            _import_step(
                step_slugs[sid],
                dict(raw, __id__=sid),
                id_to_slug=id_to_slug,
                step_slugs=step_slugs,
                known_vars=known_vars,
            )
        )

    # Edges. Anything pointing at an `end` step (or nowhere) is left implicit.
    def edges_from(sid: str, raw: dict[str, Any]) -> list[Edge]:
        frm = step_slugs[sid]
        out: list[Edge] = []

        def add(target: Any, branch: str | None = None, kind: str = "sequence") -> None:
            for tid in target if isinstance(target, list) else [target]:
                if isinstance(tid, str) and tid in step_slugs:
                    out.append(Edge(frm=frm, to=step_slugs[tid], branch=branch, kind=kind))

        ctype = str(raw.get("type") or "action")
        if ctype in ("if-condition", "decision"):
            add(raw.get("on_true"), "on_supports")
            add(raw.get("on_false"), "on_refutes")
            fuzzy = raw.get("x_org_fuzzy_condition")
            if isinstance(fuzzy, dict):
                add(fuzzy.get("on_indeterminate"), "default")
                add(fuzzy.get("on_unavailable"), "on_unavailable")
        elif ctype == "switch-condition":
            for targets in (raw.get("cases") or {}).values():
                add(targets, "default")
        elif ctype in ("while-condition", "loop"):
            add(raw.get("on_true"), "on_supports")  # loop body (`do:`)
            add(raw.get("on_completion"))  # exit edge, once the condition fails
        elif ctype == "parallel":
            add(raw.get("on_completion"), None, "merge")
        else:
            add(raw.get("on_completion"))
            add(raw.get("on_success"))
            add(raw.get("on_failure"))
        return out

    for sid, raw in workflow.items():
        if sid not in control:
            pb.edges += edges_from(sid, raw)

    # Order steps by traversal from workflow_start so document order reads as flow.
    pb.steps = _in_flow_order(pb, src, workflow, step_slugs, control)
    pb.meta = _import_frontmatter(src, pb, known_vars)
    pb.description = str(src.get("description") or "").strip()
    return pb


def _in_flow_order(pb, src, workflow, step_slugs, control) -> list[Step]:
    """Depth-first from `workflow_start`; unreachable steps keep source order."""
    by_slug = {s.slug: s for s in pb.steps}
    succ: dict[str, list[str]] = {}
    for e in pb.edges:
        succ.setdefault(e.frm, []).append(e.to)
    for sid, raw in workflow.items():
        if str(raw.get("type")) == "parallel" and sid in step_slugs:
            succ.setdefault(step_slugs[sid], [])
            succ[step_slugs[sid]] = [step_slugs[t] for t in (raw.get("next_steps") or []) if t in step_slugs] + succ[
                step_slugs[sid]
            ]

    roots: list[str] = []
    start = src.get("workflow_start")
    if isinstance(start, str) and start in workflow:
        first = workflow[start].get("on_completion") if control.get(start) == "start" else start
        if isinstance(first, str) and first in step_slugs:
            roots.append(step_slugs[first])

    ordered: list[str] = []
    seen: set[str] = set()

    def walk(slug: str) -> None:
        if slug in seen or slug not in by_slug:
            return
        seen.add(slug)
        ordered.append(slug)
        for nxt in succ.get(slug, []):
            walk(nxt)

    for root in roots:
        walk(root)
    for step in pb.steps:  # unreachable / disconnected steps still get emitted
        walk(step.slug)
    return [by_slug[s] for s in ordered]


def _import_frontmatter(src: dict[str, Any], pb: Playbook, known_vars: set[str]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    x_hunt = src.get("x_hunt") if isinstance(src.get("x_hunt"), dict) else {}

    types = src.get("playbook_types")
    meta["type"] = (types[0] if isinstance(types, list) and types else None) or x_hunt.get("hunt_type") or "investigation"
    meta["name"] = pb.name

    labels = [str(x) for x in (src.get("labels") or [])]
    techniques = [str(t) for t in (x_hunt.get("attack_techniques") or [])]
    for ref in src.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("source_name") or "").lower() == "mitre-attack" and ref.get("external_id"):
            techniques.append(str(ref["external_id"]))
            continue
        # Most real playbooks cite ATT&CK as a bare link or a name like
        # "MITRE ATT&CK - T1566.001", with no `source_name`; read those too.
        blob = f"{ref.get('name', '')} {ref.get('url', '')}"
        if "attack.mitre.org" in blob or "att&ck" in blob.lower():
            techniques += [f"{t}.{s}" if s else t for t, s in _TECHNIQUE_IN_TEXT.findall(blob)]
    attack = sorted({f"attack.{t.lower()}" for t in techniques if re.match(r"^T\d{4}", t, re.I)})
    meta["labels"] = ["hunt"] + [x for x in labels if x != "hunt"] + attack

    for marking in src.get("markings") or []:
        m = re.match(r"marking-tlp--(\w+)", str(marking))
        if m:
            meta["tlp"] = m.group(1).lower()
    severity = _ordinal_severity(src.get("severity"))
    if severity:
        meta["severity"] = severity

    hypothesis = x_hunt.get("hypothesis") or src.get("description")
    meta["hypothesis"] = (
        str(hypothesis).strip()
        if hypothesis
        else "TODO: state the adversary behaviour this hunt tests (imported from CACAO)."
    )
    if not attack:
        meta["labels"].append("TODO-attack-technique")

    # ATT&CK references are regenerated from `labels:` on export, so dropping the
    # generated copies here keeps a round-trip from accumulating duplicates.
    refs: list[dict[str, Any]] = []
    seen_refs: set[tuple[str, str]] = set()
    for r in src.get("external_references") or []:
        if not isinstance(r, dict):
            continue
        if str(r.get("source_name") or "").lower() == "mitre-attack" and attack:
            continue
        ref = {"name": r.get("name") or r.get("source_name") or "reference"}
        if r.get("url"):
            ref["url"] = r["url"]
        key = (ref["name"], ref.get("url", ""))
        if key not in seen_refs:
            seen_refs.add(key)
            refs.append(ref)
    if refs:
        meta["references"] = refs

    parameters: dict[str, Any] = {}
    for name, spec in (src.get("playbook_variables") or {}).items():
        spec = spec if isinstance(spec, dict) else {}
        entry: dict[str, Any] = {"type": spec.get("x_hunt_type") or "string"}
        if spec.get("value") not in (None, ""):
            entry["default"] = spec["value"]
        if spec.get("description"):
            entry["description"] = spec["description"]
        parameters[_clean_var(name)] = entry
    if parameters:
        meta["parameters"] = parameters

    targets, _ = _import_definitions(src)
    used = {s.target for s in pb.steps if s.target}
    if not targets and used:
        targets = {slug: {"category": "unknown", "name": slug} for slug in sorted(used)}
    meta["targets"] = targets or {"source": {"category": "unknown", "name": "TODO: name the data source"}}

    if isinstance(x_hunt.get("guardrails"), dict):
        meta["guardrails"] = x_hunt["guardrails"]

    meta["x_cacao_source"] = {k: src[k] for k in ("id", "spec_version", "created", "created_by") if src.get(k)}
    return meta


def cacao_to_markdown(defn: Any) -> str:
    """CACAO playbook -> hunt.md source (a draft; `TODO`s mark what needs an author)."""
    from huntmd.core import playbook_to_markdown

    return playbook_to_markdown(cacao_to_playbook(defn))
