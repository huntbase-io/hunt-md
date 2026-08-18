"""hunt.md ⇄ Huntbase playbook-definition core (parse, emit, validate).

Definition shape targeted (see src/api/workbench/hunt_definitions.py):
    {"hunt": {"name", "meta"}, "nodes": [
       {"id", "type", "label", "config"|"primitive_config",
        "parents": [{"id", "branch"?, "kind"?}]}]}
Node types: query | collection | action | checkpoint | task | analytic.
Edges live on each node's ``parents`` (branch = on_supports|on_refutes|default;
kind = sequence|merge).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

# --- constants --------------------------------------------------------------

# hunt.md step-kind -> Huntbase node type.
_KIND_TO_TYPE = {
    "query": "query",
    "collection": "collection",
    "agent": "analytic",
    "decision": "checkpoint",
    "task": "task",
    "action": "action",
}
_TYPE_TO_KIND = {v: k for k, v in _KIND_TO_TYPE.items()}
_PRIMITIVE_KINDS = {"query", "collection"}

# Fenced-block language -> kind (a DSL language => query).
_BLOCK_LANG_KIND = {"agent": "agent", "manual": "task", "action": "action", "collect": "collection"}
# Languages the Huntbase runtime can execute (others: portability lint).
_HUNTBASE_DSLS = {"kql", "spl", "esql", "esdsl", "aql", "mysql", "osquery", "sqlite", "cypher", "stix"}
# Known languages for the open format (broader than Huntbase's executable set).
_KNOWN_DSLS = _HUNTBASE_DSLS | {"sql", "eql", "sigma", "yara", "kestrel"}

_SEVERITY_ORDINAL = {"critical", "high", "medium", "low"}

#: TLP:2.0 sharing levels, least to most restricted. Used by `--max-tlp` so a
#: public repository can mechanically reject hunts that shouldn't leave the org.
_TLP_RANK = {"clear": 0, "white": 0, "green": 1, "amber": 2, "amber+strict": 3, "red": 4}

#: Agent safety posture (SPEC §8.1). Defaults are the *safe* value: a hunt that
#: omits the block still gets them, and relaxing one shows up in review.
_GUARDRAIL_DEFAULTS = {
    "telemetry": "untrusted",
    "evidence": "citation_required",
    "missing_data": "not_benign",
    "claims": "no_unsupported",
}
#: Allowed values per guardrail; the first is the safe default.
_GUARDRAIL_VALUES = {
    "telemetry": ("untrusted", "trusted"),
    "evidence": ("citation_required", "none"),
    "missing_data": ("not_benign", "ignorable"),
    "claims": ("no_unsupported", "permitted"),
}

#: Ordinal confidence for `if~:` (SPEC §7.2). Numeric thresholds are tolerated
#: but bucketed — an LLM's 0.8 is not calibrated, so precision there is fiction.
_CONFIDENCE_ORDINALS = ("high", "medium", "low")


def effective_guardrails(meta: dict[str, Any], step_attrs: dict[str, Any] | None = None) -> dict[str, str]:
    """Document guardrails over the defaults, then any step-level narrowing."""
    resolved = dict(_GUARDRAIL_DEFAULTS)
    for source in (meta.get("guardrails"), (step_attrs or {}).get("guardrails")):
        if isinstance(source, dict):
            resolved.update({str(k): str(v) for k, v in source.items()})
    return resolved


def bucket_confidence(value: Any) -> str | None:
    """Numeric confidence -> ordinal (SPEC §7.2): >=0.8 high, >=0.5 medium, else low."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in _CONFIDENCE_ORDINALS:
        return text
    try:
        n = float(text)
    except ValueError:
        return None
    return "high" if n >= 0.8 else "medium" if n >= 0.5 else "low"


def _str_representer(dumper, data: str):
    """Dump multi-line strings (queries, objectives) as readable literal blocks."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


class _BlockDumper(yaml.SafeDumper):
    """Private dumper: block-style multi-line strings, scoped to this module.

    Registered on a subclass (not the shared ``yaml.SafeDumper``) so importing
    this module does NOT change YAML serialization for the rest of the process —
    important when it's vendored into a larger service.
    """


_BlockDumper.add_representer(str, _str_representer)


def dump_yaml(data, **kwargs) -> str:
    """yaml.safe_dump equivalent using the module-private block dumper.

    Public so the CLI (and vendoring hosts) can serialize a definition without
    re-registering a global representer.
    """
    return yaml.dump(data, Dumper=_BlockDumper, **kwargs)


_dump = dump_yaml  # internal alias
_ARROW = re.compile(r"^(?:→|->)\s*(.+?)\s*$")
_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


class ConversionError(ValueError):
    """Raised when hunt.md or a definition can't be parsed/converted."""


# --- IR ---------------------------------------------------------------------


@dataclass
class Edge:
    frm: str
    to: str
    branch: str | None = None  # on_supports | on_refutes | default
    kind: str = "sequence"  # sequence | merge


@dataclass
class Step:
    slug: str
    kind: str  # query|collection|agent|decision|task|action|parallel|subplaybook|loop|group
    label: str = ""
    lang: str | None = None
    target: str | None = None
    params: dict[str, str] = field(default_factory=dict)
    body: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)
    # decision
    condition: str | None = None
    fuzzy: bool = False
    confidence: float | str | None = None  # ordinal preferred; numeric tolerated
    judge: str | None = None
    # `unavailable: → end` closes a hunt on data it never examined (SPEC §7.2).
    # The edge itself vanishes (end is implicit), so the intent is recorded here.
    unavailable_to_end: bool = False
    # switch/parallel/subplaybook (kept for round-trip + linting)
    branches: list[str] = field(default_factory=list)
    join: str | None = None
    switch_cases: list[tuple[str, str]] = field(default_factory=list)
    run_target: str | None = None


@dataclass
class Playbook:
    name: str = ""
    description: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)


# --- parse: hunt.md -> Playbook ---------------------------------------------


def _split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    text = text.lstrip("﻿")
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        raise ConversionError("Unterminated YAML frontmatter (missing closing '---').")
    fm_raw = text[3:end]
    body = text[end + 4 :]
    try:
        fm = yaml.safe_load(fm_raw) or {}
    except yaml.YAMLError as exc:
        raise ConversionError(f"Invalid frontmatter YAML: {exc}") from exc
    if not isinstance(fm, dict):
        raise ConversionError("Frontmatter must be a YAML mapping.")
    return fm, body


def _parse_info_string(info: str) -> tuple[str, dict[str, Any]]:
    """`kql target=siem params=(days=lookback) out=$x` -> (lang, attrs)."""
    parts = info.strip().split(None, 1)
    lang = parts[0] if parts else ""
    rest = parts[1] if len(parts) > 1 else ""
    attrs: dict[str, Any] = {}
    # params=(...) first (may contain commas)
    m = re.search(r"params=\(([^)]*)\)", rest)
    if m:
        params: dict[str, str] = {}
        for pair in m.group(1).split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()
        attrs["params"] = params
        rest = rest[: m.start()] + rest[m.end() :]
    for tok in rest.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            attrs[k.strip()] = v.strip()
    return lang, attrs


def _extract_inner_yaml(body: str) -> tuple[dict[str, Any], str]:
    """Pull a leading ``~~~yaml ... ~~~`` block out of a fenced-block body."""
    lines = body.splitlines()
    if lines and lines[0].strip().startswith("~~~"):
        for i in range(1, len(lines)):
            if lines[i].strip().startswith("~~~"):
                inner = "\n".join(lines[1:i])
                try:
                    parsed = yaml.safe_load(inner) or {}
                except yaml.YAMLError:
                    parsed = {}
                return (parsed if isinstance(parsed, dict) else {}), "\n".join(lines[i + 1 :]).strip()
    return {}, body


def _iter_sections(body: str):
    """Yield (level, slug, kind_override, lines) for each ## / ### heading."""
    cur: list[str] | None = None
    header: tuple[int, str, str | None] | None = None
    pre: list[str] = []
    for line in body.splitlines():
        m = re.match(r"^(#{2,3})\s(.*)$", line)
        if m:
            if header is not None:
                yield (*header, cur or [])
            level = len(m.group(1))
            title = m.group(2).strip()
            kind_override = None
            km = re.search(r"\[(\w+)\]\s*$", title)
            if km:
                kind_override = km.group(1)
                title = title[: km.start()].strip()
            slug = title.strip().lower().replace(" ", "-")
            header = (level, slug, kind_override)
            cur = []
        elif header is None:
            pre.append(line)
        else:
            cur.append(line)
    if header is not None:
        yield (*header, cur or [])
    yield ("__pre__", "\n".join(pre))  # sentinel carrying pre-section prose


def _parse_section(slug: str, kind_override: str | None, lines: list[str], parent: str | None):
    """Parse one section's body into a Step + its outgoing edges (as (to, branch, kind))."""
    step = Step(slug=slug, kind="group", label=slug.split("/")[-1].replace("-", " "))
    out_edges: list[tuple[str, str | None, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.strip()
        # fenced ``` block. CommonMark fence rule: the opening backtick run has a
        # length; the block closes only on a line that is a bare backtick run of
        # AT LEAST that length. So a body containing ``` is preserved by opening
        # with a longer fence (````), instead of being silently truncated.
        if line.startswith("```"):
            fence_len = len(line) - len(line.lstrip("`"))
            info = line[fence_len:].strip()
            j = i + 1
            block: list[str] = []
            while j < n:
                closing = lines[j].strip()
                if closing and set(closing) == {"`"} and len(closing) >= fence_len:
                    break
                block.append(lines[j])
                j += 1
            body = "\n".join(block)
            lang, attrs = _parse_info_string(info)
            step.lang = lang
            step.target = attrs.get("target")
            step.params = attrs.get("params", {})
            step.attrs.update({k: v for k, v in attrs.items() if k not in ("params", "target")})
            step.kind = _BLOCK_LANG_KIND.get(lang, "query")
            inner, text = _extract_inner_yaml(body)
            step.attrs.update(inner)
            step.body = text
            # An `agent` block body IS YAML (objective/tools/context/…) — parse
            # it into attrs (queries/manual/action keep their body as text).
            if step.kind == "agent":
                try:
                    parsed = yaml.safe_load(text) or {}
                    if isinstance(parsed, dict):
                        step.attrs.update(parsed)
                except yaml.YAMLError:
                    pass
            i = j + 1
            continue
        # step-level ~~~yaml attribute block
        if line.startswith("~~~"):
            j = i + 1
            block = []
            while j < n and not lines[j].strip().startswith("~~~"):
                block.append(lines[j])
                j += 1
            try:
                parsed = yaml.safe_load("\n".join(block)) or {}
                if isinstance(parsed, dict):
                    step.attrs.update(parsed)
            except yaml.YAMLError:
                pass
            i = j + 1
            continue
        # control-flow lines
        if line.startswith("if~:") or line.startswith("if:"):
            step.kind = "decision"
            step.fuzzy = line.startswith("if~:")
            cond = line.split(":", 1)[1].strip()
            # `(confidence: high, judge=hunter)` — ordinal, preferred — or the
            # legacy `(confidence >= 0.8, judge=hunter)`. Either part may be absent.
            qualifier = re.search(r"\(([^)]*)\)\s*$", cond)
            if qualifier:
                inner = qualifier.group(1)
                cm = re.search(r"confidence\s*[:>=]+\s*([\w.]+)", inner)
                jm = re.search(r"judge\s*=\s*(\w+)", inner)
                if cm or jm:
                    if cm:
                        raw = cm.group(1)
                        step.confidence = float(raw) if re.fullmatch(r"[\d.]+", raw) else raw.lower()
                    if jm:
                        step.judge = jm.group(1)
                    cond = cond[: qualifier.start()].strip()
            step.condition = cond.strip().strip("`\"'")
        elif line.startswith("switch:"):
            step.kind = "decision"
            step.condition = line.split(":", 1)[1].strip().strip("`")
        elif line.startswith("while:"):
            step.kind = "loop"
            step.condition = line.split(":", 1)[1].strip()
        elif line.startswith("parallel:"):
            step.kind = "parallel"
        elif line.startswith("run:"):
            step.kind = "subplaybook"
            step.run_target = line.split(":", 1)[1].strip()
        elif line.startswith("then:"):
            t = _target_of(line.split(":", 1)[1])
            if t:
                out_edges.append((t, "on_supports", "sequence"))
        elif line.startswith("else:"):
            t = _target_of(line.split(":", 1)[1])
            if t:
                out_edges.append((t, "on_refutes", "sequence"))
        elif line.startswith("indeterminate:"):
            t = _target_of(line.split(":", 1)[1])
            if t:
                out_edges.append((t, "default", "sequence"))
        elif line.startswith("unavailable:"):
            t = _target_of(line.split(":", 1)[1])
            if t == "end":
                step.unavailable_to_end = True
            elif t:
                out_edges.append((t, "on_unavailable", "sequence"))
        elif line.startswith("join:"):
            step.join = _target_of(line.split(":", 1)[1])
        elif line.startswith("do:"):
            t = _target_of(line.split(":", 1)[1])
            if t:
                out_edges.append((t, None, "sequence"))
        elif line.startswith("- "):
            # switch case  - "value" → target   OR  parallel branch  - → target
            body = line[2:].strip()
            cm = re.match(r'"([^"]*)"\s*(?:→|->)\s*(.+)$|(default)\s*(?:→|->)\s*(.+)$', body)
            if cm:
                value = cm.group(1) if cm.group(1) is not None else cm.group(3)
                tgt = (cm.group(2) or cm.group(4) or "").strip()
                step.switch_cases.append((value, tgt))
            else:
                am = _ARROW.match(body)
                if am:
                    step.branches.append(am.group(1).strip())
        elif _ARROW.match(line):
            out_edges.append((_ARROW.match(line).group(1).strip(), None, "sequence"))
        i += 1

    if kind_override:
        step.kind = kind_override
    if parent:
        step.slug = f"{parent}/{slug}"
        out_edges = [(f"{parent}/{t}" if "/" not in t and t != "end" else t, b, k) for t, b, k in out_edges]
    return step, out_edges


def _target_of(s: str) -> str | None:
    # Authors annotate branches (`then: → x   # why`); the comment isn't a slug.
    s = re.sub(r"\s+#.*$", "", s.strip())
    m = _ARROW.match(s.strip())
    return m.group(1).strip() if m else (s.strip() or None)


def parse_markdown(text: str) -> Playbook:
    fm, body = _split_frontmatter(text)
    pb = Playbook(meta=dict(fm))
    sections: list[tuple[str, str | None, list[str], str | None]] = []
    parent: str | None = None
    for item in _iter_sections(body):
        if item[0] == "__pre__":
            pre = item[1]
            # H1 title + description
            h1 = re.search(r"^#\s(.+)$", pre, re.M)
            if h1:
                pb.name = h1.group(1).strip()
                after = pre[h1.end() :].strip()
                pb.description = after
            continue
        level, slug, kind_override, lines = item
        if level == 3:
            sections.append((slug, kind_override, lines, parent))
        else:
            parent = slug if _is_group_header(lines) else None
            sections.append((slug, kind_override, lines, None))
    pb.name = pb.name or fm.get("name", "Untitled hunt")

    parsed_steps: list[tuple[Step, list[tuple[str, str | None, str]]]] = []
    for slug, ko, lines, par in sections:
        step, oe = _parse_section(slug, ko, lines, par)
        parsed_steps.append((step, oe))
    _wire_edges(pb, parsed_steps)
    return pb


def _is_group_header(lines: list[str]) -> bool:
    """A ## with no content of its own (only ### children follow) is a group."""
    return not any(
        ln.strip().startswith(("```", "if:", "if~:", "switch:", "while:", "parallel:", "run:", "→", "->"))
        for ln in lines
    )


def _wire_edges(pb: Playbook, parsed: list[tuple[Step, list[tuple[str, str | None, str]]]]) -> None:
    real = [(s, oe) for s, oe in parsed if s.kind not in ("group",)]
    pb.steps = [s for s, _ in real]
    explicit_targets: set[str] = set()

    # A `##` group header is not a node; a jump to it resolves to the group's
    # first `###` child step (spec §7.1).
    group_slugs = {s.slug for s, _ in parsed if s.kind == "group"}
    group_first: dict[str, str] = {}
    for s, _ in real:
        head = s.slug.rsplit("/", 1)[0] if "/" in s.slug else None
        if head in group_slugs and head not in group_first:
            group_first[head] = s.slug

    def _resolve(to: str) -> str:
        return group_first.get(to, to)

    def add(frm: str, to: str, branch: str | None, kind: str) -> None:
        to = _resolve(to)
        if to == "end":
            return
        pb.edges.append(Edge(frm=frm, to=to, branch=branch, kind=kind))
        explicit_targets.add(to)

    # explicit edges + parallel/join/switch expansion
    for s, oe in real:
        for to, branch, kind in oe:
            add(s.slug, to, branch, kind)
        if s.kind == "parallel":
            for br in s.branches:
                explicit_targets.add(br)  # branch entries are roots seeded by parallel
            if s.join:
                for br in s.branches:
                    add(br, s.join, None, "merge")
        if s.kind == "decision" and s.switch_cases:
            for _val, tgt in s.switch_cases:
                add(s.slug, tgt, "default", "sequence")

    # document-order sequence edges (only where nothing explicit already links)
    prev: Step | None = None
    for s, oe in real:
        terminates = bool(oe) or s.kind in ("parallel", "decision", "loop", "subplaybook")
        if (
            prev is not None
            and prev.kind != "parallel"
            and s.slug not in explicit_targets
            and not _terminates(prev, parsed)
        ):
            pb.edges.append(Edge(frm=prev.slug, to=s.slug, kind="sequence"))
        prev = s


def _terminates(step: Step, parsed) -> bool:
    for s, oe in parsed:
        if s.slug == step.slug:
            return bool(oe) or s.kind in ("parallel", "decision", "loop", "subplaybook")
    return False


# --- emit: Playbook -> definition -------------------------------------------


def _rewrite_placeholders(body: str, params: dict[str, str]) -> str:
    """Map query placeholders to the bound playbook-parameter names.

    ``params=(days=lookback)`` + ``{{days}}`` -> ``{{lookback}}`` so the query
    references the real playbook parameter (Huntbase substitutes ``{{name}}``).
    """
    for qname, source in params.items():
        src = source.lstrip("$")
        body = re.sub(r"\{\{\s*" + re.escape(qname) + r"\s*\}\}", "{{" + src + "}}", body)
    return body


def playbook_to_definition(pb: Playbook) -> dict[str, Any]:
    parents: dict[str, list[dict[str, Any]]] = {}
    for e in pb.edges:
        entry: dict[str, Any] = {"id": e.frm}
        if e.branch:
            entry["branch"] = e.branch
        if e.kind and e.kind != "sequence":
            entry["kind"] = e.kind
        # Dedupe: e.g. two switch cases pointing at the same step would otherwise
        # emit duplicate parent entries the runtime then ingests twice.
        bucket = parents.setdefault(e.to, [])
        if entry not in bucket:
            bucket.append(entry)

    nodes: list[dict[str, Any]] = []
    for s in pb.steps:
        if s.kind in ("parallel", "group"):
            continue
        node_type = _KIND_TO_TYPE.get(s.kind, "task")
        node: dict[str, Any] = {"id": s.slug, "type": node_type, "label": s.label or s.slug}
        if s.kind in _PRIMITIVE_KINDS:
            node["primitive_config"] = {
                "dsl": s.lang or "sqlite",
                "content": _rewrite_placeholders(s.body, s.params),
                "label": node["label"],
            }
            # Round-trip hint (the abstract target maps to a connection at launch;
            # the runtime ignores this extra key, the exporter reads it back).
            if s.target:
                node["primitive_config"]["target"] = s.target
        else:
            node["config"] = _config_for(s)
        if s.slug in parents:
            node["parents"] = parents[s.slug]
        nodes.append(node)

    return {"hunt": {"name": pb.name, "meta": _hunt_meta(pb)}, "nodes": nodes}


def _config_for(s: Step) -> dict[str, Any]:
    if s.kind == "agent":
        cfg = {"objective": s.attrs.get("objective", s.body).strip()}
        for k in ("tools", "context", "success_criteria", "max_iterations", "in", "out"):
            if k in s.attrs:
                cfg[k] = s.attrs[k]
        return cfg
    if s.kind == "decision":
        cfg: dict[str, Any] = {
            "checkpoint_type": "mandatory" if s.fuzzy else s.attrs.get("checkpoint_type", "advisory"),
            "condition": s.condition or "",
        }
        if s.fuzzy:
            cfg.update({"fuzzy": True, "confidence": s.confidence, "judge": s.judge})
        if s.switch_cases:
            cfg["switch_cases"] = [{"value": v, "to": t} for v, t in s.switch_cases]
        return cfg
    if s.kind == "task":
        return {"instructions": s.body.strip(), "assignee": s.target}
    if s.kind == "action":
        return {
            "instructions": s.body.strip(),
            "action_approval": s.attrs.get("approval"),
            "track": s.attrs.get("track"),
            "target": s.target,
        }
    return {"body": s.body.strip(), **s.attrs}


def _hunt_meta(pb: Playbook) -> dict[str, Any]:
    keep = ("labels", "severity", "tlp", "hypothesis", "references", "parameters", "targets", "type")
    meta = {k: pb.meta[k] for k in keep if k in pb.meta}
    # Always resolved, never omitted: a runtime must receive the safety posture
    # even when the author didn't write the block (SPEC §8.1).
    meta["guardrails"] = effective_guardrails(pb.meta)
    return meta


def markdown_to_definition(text: str) -> dict[str, Any]:
    return playbook_to_definition(parse_markdown(text))


# --- emit: Playbook -> hunt.md ----------------------------------------------

#: Frontmatter key order (SPEC §3.1) — everything else keeps its own order after.
_FM_ORDER = (
    "id",
    "type",
    "name",
    "labels",
    "tlp",
    "severity",
    "hypothesis",
    "references",
    "parameters",
    "targets",
)
#: Attribute keys rendered by native syntax, so they never repeat in a Tier-2 block.
_NATIVE_ATTRS = {
    "objective",
    "tools",
    "context",
    "success_criteria",
    "max_iterations",
    "approval",
    "in",
    "out",
    "target",
    "params",
    "description",
}


def _fm_dump(meta: dict[str, Any]) -> str:
    ordered = {k: meta[k] for k in _FM_ORDER if k in meta}
    ordered.update({k: v for k, v in meta.items() if k not in ordered})
    return _dump(ordered, sort_keys=False, default_flow_style=False, allow_unicode=True).strip()


def _info_string(s: Step) -> str:
    bits = []
    if s.target:
        bits.append(f"target={s.target}")
    if s.params:
        bits.append("params=(" + ", ".join(f"{k}={v}" for k, v in s.params.items()) + ")")
    for key in ("in", "out"):
        value = s.attrs.get(key)
        if value:
            rendered = ",".join(str(v) for v in value) if isinstance(value, list) else str(value)
            bits.append(f"{key}={rendered}")
    return (" " + " ".join(bits)) if bits else ""


def playbook_to_markdown(pb: Playbook) -> str:
    """Serialise the IR back to hunt.md (Tier-1 native syntax, Tier-2 for the rest).

    Used by the decompilers (definition and CACAO import). Emits every step kind
    — including `parallel`, `while:` and `run:` — so nothing is dropped on the
    way back to source (SPEC §2).
    """
    out: list[str] = []
    if pb.meta:
        out += ["---", _fm_dump(pb.meta), "---", ""]
    out.append(f"# {pb.name or 'Untitled hunt'}\n")
    if pb.description:
        out.append(pb.description.strip() + "\n")

    children: dict[str, list[tuple[str, str | None]]] = {}
    indegree: dict[str, int] = {}
    for e in pb.edges:
        children.setdefault(e.frm, []).append((e.to, e.branch))
        indegree[e.to] = indegree.get(e.to, 0) + 1
    order = [s.slug for s in pb.steps]

    for idx, s in enumerate(pb.steps):
        out.append(f"## {s.slug}")
        info = _info_string(s)
        extra = {k: v for k, v in s.attrs.items() if k not in _NATIVE_ATTRS}

        if s.kind in ("query", "collection"):
            lang = "collect" if s.kind == "collection" else (s.lang or "sql")
            out += [f"```{lang}{info}", s.body.rstrip(), "```"]
        elif s.kind == "agent":
            directive = {k: s.attrs[k] for k in ("objective", "context", "tools", "success_criteria", "max_iterations") if k in s.attrs}
            directive.setdefault("objective", s.body.strip())
            out += [f"```agent{info}", _dump(directive, sort_keys=False, allow_unicode=True).strip(), "```"]
        elif s.kind in ("task", "action"):
            block = "manual" if s.kind == "task" else "action"
            out.append(f"```{block}{info}")
            if s.kind == "action" and s.attrs.get("approval"):
                out += ["~~~yaml", f"approval: {s.attrs['approval']}", "~~~"]
            out += [s.body.rstrip(), "```"]
        elif s.kind == "decision":
            if s.switch_cases:
                out.append(f"switch: `{s.condition or ''}`")
                width = max((len(f'"{v}"') for v, _ in s.switch_cases), default=0)
                for value, target in s.switch_cases:
                    label = "default" if str(value).lower() == "default" else f'"{value}"'
                    out.append(f"- {label.ljust(width)} → {target}")
            else:
                cond = f"`{s.condition or ''}`"
                if s.fuzzy:
                    qualifiers = []
                    if s.confidence is not None:
                        # Ordinal is written as `confidence: high`; a legacy
                        # numeric keeps its threshold form so nothing is lost.
                        numeric = isinstance(s.confidence, (int, float))
                        qualifiers.append(
                            f"confidence >= {s.confidence}" if numeric else f"confidence: {s.confidence}"
                        )
                    if s.judge:
                        qualifiers.append(f"judge={s.judge}")
                    cond = f'"{s.condition or ""}"' + (f" ({', '.join(qualifiers)})" if qualifiers else "")
                out.append(f"{'if~:' if s.fuzzy else 'if:'} {cond}")
                for branch, keyword in (
                    ("on_supports", "then"),
                    ("default", "indeterminate"),
                    ("on_unavailable", "unavailable"),
                    ("on_refutes", "else"),
                ):
                    for to, br in children.get(s.slug, []):
                        if br == branch:
                            out.append(f"{keyword}: → {to}")
                if s.unavailable_to_end:
                    out.append("unavailable: → end")
        elif s.kind == "loop":
            bound = f" (max_iterations={s.attrs['max_iterations']})" if s.attrs.get("max_iterations") else ""
            out.append(f"while: {s.condition or ''}{bound}")
            # `do:` is the loop body; an unbranched successor is the exit edge and
            # falls through to the arrow logic below.
            for to, br in children.get(s.slug, []):
                if br == "on_supports":
                    out.append(f"do: → {to}")
        elif s.kind == "parallel":
            out.append("parallel:")
            out += [f"- → {b}" for b in s.branches]
            if s.join:
                out.append(f"join: → {s.join}")
        elif s.kind == "subplaybook":
            out.append(f"run: {s.run_target or ''}")
        else:
            out.append(s.body.rstrip())

        if extra:
            out += ["~~~yaml", _dump(extra, sort_keys=False, allow_unicode=True).strip(), "~~~"]

        # Flow: document order carries the common case; emit an arrow only where
        # the successor isn't the next step in the document (SPEC §4.1).
        if s.kind not in ("decision", "parallel"):
            kids = [to for to, br in children.get(s.slug, []) if br is None]
            following = order[idx + 1] if idx + 1 < len(order) else None
            # Fall through to document order only when the next step is reached
            # from here *alone* — a step with other parents (a join, a jump
            # target) needs the edge stated, or a reparse won't rebuild it.
            implicit = kids == [following] and indegree.get(following, 0) == 1
            if not kids:
                if s.kind != "loop":
                    out.append("→ end")
            elif not implicit:
                out += [f"→ {to}" for to in kids]
        out.append("")

    return "\n".join(out).rstrip() + "\n"


# --- emit: definition -> hunt.md (best-effort inverse) ----------------------


def _slugify(text: str) -> str:
    """Readable, stable step slug from a label — lowercase, non-alphanumerics
    collapsed to a single ``-``, trimmed, capped so headings stay legible."""
    s = re.sub(r"[^a-z0-9]+", "-", str(text).strip().lower()).strip("-")
    return s[:60].rstrip("-")


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _slug_map(nodes: list[dict[str, Any]]) -> dict[str, str]:
    """Map each node id → the slug used for its heading and transitions.

    A hunt.md-authored definition already carries readable, possibly
    group-qualified ids (``id == step.slug``); those are kept verbatim so the
    round-trip is byte-stable. A **session-derived** definition carries DB
    UUIDs, which make the export unreadable — for those we derive a slug from
    the node's label (falling back to the primitive's label), dedup collisions
    with a numeric suffix, and use it for both headings and transitions so the
    graph stays legible and re-imports to a deterministic ``uuid5(slug)`` id."""
    slug_by_id: dict[str, str] = {}
    used: dict[str, int] = {}
    # Reserve authored slugs first so a derived slug can't collide with one.
    for node in nodes:
        nid = node.get("id", "")
        if nid and not _UUID_RE.match(nid):
            slug_by_id[nid] = nid
            used[nid] = 1
    for node in nodes:
        nid = node.get("id", "")
        if nid in slug_by_id:
            continue
        label = node.get("label") or (node.get("primitive_config") or {}).get("label") or ""
        base = _slugify(label) or nid
        n = used.get(base, 0) + 1
        used[base] = n
        slug_by_id[nid] = base if n == 1 else f"{base}-{n}"
    return slug_by_id


def definition_to_markdown(defn: dict[str, Any]) -> str:
    if not isinstance(defn, dict) or "nodes" not in defn:
        raise ConversionError("Not a playbook definition (missing 'nodes').")
    hunt = defn.get("hunt") or {}
    meta = dict(hunt.get("meta") or {})
    out: list[str] = ["---"]
    out.append(_dump(meta, sort_keys=False, default_flow_style=False).strip())
    out.append("---\n")
    out.append(f"# {hunt.get('name', 'Untitled hunt')}\n")

    slug_by_id = _slug_map(defn["nodes"])

    # Invert parents → children (with branch) so flow is reconstructed. Keyed by
    # the readable slug on both sides so headings and transitions line up.
    children: dict[str, list[tuple[str, str | None]]] = {}
    for node in defn["nodes"]:
        child_slug = slug_by_id.get(node.get("id", ""), node.get("id", ""))
        for p in node.get("parents") or []:
            parent_slug = slug_by_id.get(p.get("id", ""), p.get("id", ""))
            children.setdefault(parent_slug, []).append((child_slug, p.get("branch")))
    # Branch value → hunt.md keyword. Unknown branches fall back to
    # `indeterminate` (never `then`/on_supports) so an unrecognized branch can't
    # be silently routed to the positive/action arm.
    _branch_kw = {
        "on_supports": "then",
        "on_refutes": "else",
        "default": "indeterminate",
        "on_unavailable": "unavailable",
    }

    for node in defn["nodes"]:
        nid = node.get("id", "")
        slug = slug_by_id.get(nid, nid)
        ntype = node.get("type", "query")
        cfg = node.get("config") or {}
        out.append(f"## {slug}")
        if ntype == "query":
            pc = node.get("primitive_config") or {}
            tgt = f" target={pc['target']}" if pc.get("target") else ""
            # Emit the query's real DSL; if it's genuinely unset, use a bare
            # fence rather than fabricating `sqlite` (which would silently
            # re-import as a SQLite query). An empty info-string still parses
            # back as a query.
            out.append(f"```{pc.get('dsl') or ''}{tgt}")
            out.append(pc.get("content", "").rstrip())
            out.append("```")
        elif ntype == "collection":
            pc = node.get("primitive_config") or {}
            tgt = f" target={pc['target']}" if pc.get("target") else ""
            out.append(f"```collect{tgt}")
            out.append(pc.get("content", "").rstrip())
            out.append("```")
        elif ntype == "analytic":
            out.append("```agent")
            out.append(_dump({k: cfg[k] for k in cfg if k != "body"}, sort_keys=False).strip())
            out.append("```")
        elif ntype == "checkpoint":
            if cfg.get("switch_cases"):
                out.append(f"switch: `{cfg.get('condition', '')}`")
                for case in cfg["switch_cases"]:
                    to = slug_by_id.get(case.get("to"), case.get("to"))
                    out.append(f'- "{case.get("value")}" → {to}')
            elif cfg.get("fuzzy"):
                qual = []
                if cfg.get("confidence"):
                    qual.append(f"confidence: {cfg['confidence']}")
                if cfg.get("judge"):
                    qual.append(f"judge={cfg['judge']}")
                suffix = f" ({', '.join(qual)})" if qual else ""
                out.append(f'if~: "{cfg.get("condition", "")}"{suffix}')
            else:
                out.append(f"if: `{cfg.get('condition', '')}`")
        elif ntype == "action":
            tgt = f" target={cfg['target']}" if cfg.get("target") else ""
            out.append(f"```action{tgt}")
            if cfg.get("action_approval"):
                out += ["~~~yaml", f"approval: {cfg['action_approval']}", "~~~"]
            out.append((cfg.get("instructions") or "").rstrip())
            out.append("```")
        else:  # task
            tgt = f" target={cfg['assignee']}" if cfg.get("assignee") else ""
            out.append(f"```manual{tgt}")
            out.append((cfg.get("instructions") or "").rstrip())
            out.append("```")
        # transitions
        kids = children.get(slug, [])
        is_switch = ntype == "checkpoint" and cfg.get("switch_cases")
        if is_switch:
            pass  # case list already emitted above
        elif ntype == "checkpoint":
            for cid, branch in kids:
                out.append(f"{_branch_kw.get(branch or 'default', 'indeterminate')}: → {cid}")
        else:
            for cid, _ in kids:
                out.append(f"→ {cid}")
        if not kids and not is_switch:
            out.append("→ end")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# --- validate ---------------------------------------------------------------


@dataclass
class Issue:
    level: str  # error | warn
    slug: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper():5}] {self.slug or '-'}: {self.message}"


def validate_markdown(text: str, *, profile: str = "huntbase", max_tlp: str | None = None) -> list[Issue]:
    """Lint a hunt.md against the format + a profile.

    ``format`` checks the neutral spec only; ``huntbase`` adds that runtime's
    capability gaps; ``cacao`` adds none — every construct exports (PROFILES §2),
    so a hunt clean at ``format`` level is clean for interchange; ``misp`` warns
    where the HUNT-EX vocabulary can't classify the hunt (PROFILES §3).

    ``max_tlp`` caps the permitted sharing level: a public repository lints with
    ``max_tlp="green"`` so an ``amber``/``red`` hunt fails CI rather than being
    published by mistake.
    """
    issues: list[Issue] = []
    try:
        pb = parse_markdown(text)
    except ConversionError as exc:
        return [Issue("error", "", str(exc))]

    slugs = {s.slug for s in pb.steps}
    severity = pb.meta.get("severity")
    if isinstance(severity, str) and severity not in _SEVERITY_ORDINAL:
        issues.append(Issue("warn", "", f"severity '{severity}' not in {sorted(_SEVERITY_ORDINAL)}"))

    if max_tlp:
        issues += _check_tlp(pb, max_tlp)
    issues += _check_guardrails(pb)
    issues += _check_variables(pb)

    # edges reference existing nodes
    for e in pb.edges:
        if e.to not in slugs:
            issues.append(Issue("error", e.frm, f"edge → '{e.to}' targets an unknown step"))

    _decision_slugs = {s.slug for s in pb.steps if s.kind == "decision"}
    targeted = {e.to for e in pb.edges}
    for s in pb.steps:
        if s.kind == "query" and not s.target:
            issues.append(Issue("error", s.slug, "query has no target= source"))
        if s.kind == "query" and s.lang and s.lang not in _KNOWN_DSLS:
            issues.append(Issue("warn", s.slug, f"unknown query language '{s.lang}'"))
        if s.kind == "agent":
            if "tools" not in s.attrs:
                issues.append(Issue("warn", s.slug, "agent step has no tools allowlist"))
            if "max_iterations" not in s.attrs:
                issues.append(Issue("warn", s.slug, "agent step has no max_iterations bound"))
        if s.kind == "decision" and s.fuzzy:
            has_indet = any(e.frm == s.slug and e.branch == "default" for e in pb.edges)
            if not has_indet:
                issues.append(Issue("error", s.slug, "fuzzy if~: has no indeterminate: branch"))
            if isinstance(s.confidence, (int, float)):
                issues.append(
                    Issue(
                        "warn",
                        s.slug,
                        f"numeric confidence {s.confidence} is not calibrated across models or runs; "
                        f"prefer ordinal (confidence: {bucket_confidence(s.confidence)})",
                    )
                )
            if s.confidence is not None and isinstance(s.confidence, str) and s.confidence not in _CONFIDENCE_ORDINALS:
                issues.append(
                    Issue("error", s.slug, f"confidence '{s.confidence}' not in {list(_CONFIDENCE_ORDINALS)}")
                )
            # "We couldn't look" must not end the hunt (SPEC §7.2, §8.1).
            if s.unavailable_to_end and effective_guardrails(pb.meta, s.attrs)["missing_data"] == "not_benign":
                issues.append(
                    Issue(
                        "error",
                        s.slug,
                        "unavailable: → end closes the hunt on telemetry it never examined; "
                        "route it to a human or a collection step (or set guardrails.missing_data: ignorable)",
                    )
                )
        if s.kind == "action":
            # Gated = explicit approval OR reached only through a decision
            # (SPEC §9: destructive actions sit behind approval OR a decision).
            gated = s.attrs.get("approval") == "required" or any(
                e.to == s.slug and e.frm in _decision_slugs for e in pb.edges
            )
            if not gated:
                issues.append(
                    Issue("warn", s.slug, "action changes state but is not gated — add `approval: required` or a preceding decision")
                )
        # reachability
        if s.slug not in targeted and not _is_root_ok(s, pb):
            issues.append(Issue("warn", s.slug, "step is unreachable (no incoming edge)"))
        # Huntbase-profile capability gaps
        if profile == "huntbase":
            if s.kind == "loop":
                issues.append(Issue("error", s.slug, "while: loops are not executable on Huntbase"))
            if s.kind == "subplaybook":
                issues.append(Issue("error", s.slug, "run:/sub-playbook is not executable on Huntbase; launch it separately"))
            if s.kind == "decision" and s.switch_cases:
                issues.append(Issue("warn", s.slug, "switch: compiles to chained binary checkpoints on Huntbase"))
            for src in list(s.params.values()) + _runtime_vars(s):
                if src.startswith("$"):
                    issues.append(Issue("warn", s.slug, f"runtime variable '{src}' → uses session/entity scoping on Huntbase (no named binding)"))
    if profile == "misp":
        from huntmd.misp import misp_issues  # noqa: PLC0415 - adapters import core, not vice versa

        issues.extend(Issue(lvl, slug, msg) for lvl, slug, msg in misp_issues(pb))
    return issues


def _check_guardrails(pb: Playbook) -> list[Issue]:
    """Validate the safety posture (SPEC §8.1) and surface every relaxation."""
    issues: list[Issue] = []
    sources: list[tuple[str, Any]] = [("", pb.meta.get("guardrails"))]
    sources += [(s.slug, s.attrs.get("guardrails")) for s in pb.steps if "guardrails" in s.attrs]

    for slug, block in sources:
        if block is None:
            continue
        if not isinstance(block, dict):
            issues.append(Issue("error", slug, "guardrails: must be a mapping"))
            continue
        for key, value in block.items():
            allowed = _GUARDRAIL_VALUES.get(str(key))
            if allowed is None:
                issues.append(
                    Issue("error", slug, f"unknown guardrail '{key}'; expected one of {sorted(_GUARDRAIL_VALUES)}")
                )
            elif str(value) not in allowed:
                issues.append(Issue("error", slug, f"guardrail {key}: '{value}' not in {list(allowed)}"))

    # A weakened guardrail is legal but must be conspicuous in review.
    agentic = [s for s in pb.steps if s.kind == "agent" or (s.kind == "decision" and s.fuzzy)]
    if agentic:
        for slug, _ in sources:
            step_attrs = next((s.attrs for s in pb.steps if s.slug == slug), {}) if slug else {}
            for key, value in effective_guardrails(pb.meta, step_attrs).items():
                if key in _GUARDRAIL_VALUES and value != _GUARDRAIL_DEFAULTS[key]:
                    issues.append(
                        Issue(
                            "warn",
                            slug,
                            f"guardrail {key} relaxed to '{value}' (default '{_GUARDRAIL_DEFAULTS[key]}') — "
                            f"agent steps will run with a weaker safety posture",
                        )
                    )
    return issues


def _check_tlp(pb: Playbook, max_tlp: str) -> list[Issue]:
    """Enforce a sharing ceiling. An unmarked hunt is treated as unreviewed, not safe."""
    ceiling = _TLP_RANK.get(str(max_tlp).strip().lower())
    if ceiling is None:
        return [Issue("error", "", f"unknown --max-tlp '{max_tlp}'; expected one of {sorted(_TLP_RANK)}")]
    declared = pb.meta.get("tlp")
    if declared is None:
        return [Issue("error", "", f"no 'tlp:' declared, and this repository requires tlp <= {max_tlp}")]
    rank = _TLP_RANK.get(str(declared).strip().lower())
    if rank is None:
        return [Issue("error", "", f"unrecognised tlp '{declared}'; expected one of {sorted(_TLP_RANK)}")]
    if rank > ceiling:
        return [Issue("error", "", f"tlp '{declared}' exceeds this repository's limit of '{max_tlp}' — do not publish here")]
    return []


def _runtime_vars(s: Step) -> list[str]:
    vals: list[str] = []
    for k in ("in", "out", "context"):
        v = s.attrs.get(k)
        if isinstance(v, list):
            vals += [str(x) for x in v if str(x).startswith("$")]
    return vals


def _attr_list(step: Step, key: str) -> list[str]:
    """A step attr that may be a list or a comma-string (`out=$a,$b`)."""
    v = step.attrs.get(key)
    if v is None:
        return []
    if isinstance(v, str):
        return [t.strip() for t in v.split(",") if t.strip()]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _out_vars(step: Step) -> set[str]:
    return {v.lstrip("$") for v in _attr_list(step, "out") if v.startswith("$")}


def _check_variables(pb: Playbook) -> list[Issue]:
    """Def-before-use for `$var` dataflow, and declared-ness for `{{param}}`
    sources (the rule CONTRIBUTING.md promises). Runs at every profile — it's a
    portability/correctness check, independent of whether a runtime executes
    `$var` binding natively."""
    issues: list[Issue] = []
    declared = set(pb.meta.get("parameters") or {})
    produced: set[str] = set()
    for s in pb.steps:
        produced |= _out_vars(s)

    defined: set[str] = set()
    for s in pb.steps:
        # A parameter source (params=(q=NAME) with no `$`) must be declared.
        for src in s.params.values():
            if not src.startswith("$") and src not in declared:
                issues.append(Issue("error", s.slug, f"parameter '{src}' is not declared in frontmatter parameters:"))
        # Runtime `$var` uses — from params, in=, context, and the condition.
        used = {v.lstrip("$") for v in s.params.values() if v.startswith("$")}
        used |= {v.lstrip("$") for v in _attr_list(s, "in") if v.startswith("$")}
        used |= {v.lstrip("$") for v in _attr_list(s, "context") if v.startswith("$")}
        used |= set(re.findall(r"\$(\w+)", s.condition or ""))
        for v in sorted(used):
            if v not in produced and v not in declared:
                issues.append(Issue("error", s.slug, f"variable ${v} is used but never produced by an out="))
            elif v not in defined and v not in declared:
                issues.append(Issue("warn", s.slug, f"variable ${v} is used before it is produced"))
        defined |= _out_vars(s)
    return issues


def _is_root_ok(step: Step, pb: Playbook) -> bool:
    """A step with no incoming edge is fine if it's a parallel branch entry or the first step."""
    if pb.steps and pb.steps[0].slug == step.slug:
        return True
    for s in pb.steps:
        if s.kind == "parallel" and step.slug in s.branches:
            return True
    return False
