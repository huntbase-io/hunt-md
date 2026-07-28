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


def _str_representer(dumper: yaml.SafeDumper, data: str):
    """Dump multi-line strings (queries, objectives) as readable literal blocks."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_representer, Dumper=yaml.SafeDumper)
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
    confidence: float | None = None
    judge: str | None = None
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
        m = re.match(r"^(#{2,3})\s+(.*)$", line)
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
        # fenced ``` block
        if line.startswith("```"):
            info = line[3:].strip()
            j = i + 1
            block: list[str] = []
            while j < n and not lines[j].strip().startswith("```"):
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
            cm = re.search(r"\(confidence\s*>?=?\s*([\d.]+).*?judge=(\w+)\)", cond)
            if cm:
                step.confidence = float(cm.group(1))
                step.judge = cm.group(2)
                cond = cond[: cm.start()].strip()
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
            h1 = re.search(r"^#\s+(.+)$", pre, re.M)
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
        parents.setdefault(e.to, []).append(entry)

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
    return {k: pb.meta[k] for k in keep if k in pb.meta}


def markdown_to_definition(text: str) -> dict[str, Any]:
    return playbook_to_definition(parse_markdown(text))


# --- emit: definition -> hunt.md (best-effort inverse) ----------------------


def definition_to_markdown(defn: dict[str, Any]) -> str:
    if not isinstance(defn, dict) or "nodes" not in defn:
        raise ConversionError("Not a playbook definition (missing 'nodes').")
    hunt = defn.get("hunt") or {}
    meta = dict(hunt.get("meta") or {})
    out: list[str] = ["---"]
    out.append(yaml.safe_dump(meta, sort_keys=False, default_flow_style=False).strip())
    out.append("---\n")
    out.append(f"# {hunt.get('name', 'Untitled hunt')}\n")

    # Invert parents → children (with branch) so flow is reconstructed.
    children: dict[str, list[tuple[str, str | None]]] = {}
    for node in defn["nodes"]:
        for p in node.get("parents") or []:
            children.setdefault(p.get("id", ""), []).append((node.get("id", ""), p.get("branch")))
    _branch_kw = {"on_supports": "then", "on_refutes": "else", "default": "indeterminate"}

    for node in defn["nodes"]:
        nid = node.get("id", "")
        ntype = node.get("type", "query")
        cfg = node.get("config") or {}
        out.append(f"## {nid}")
        if ntype == "query":
            pc = node.get("primitive_config") or {}
            tgt = f" target={pc['target']}" if pc.get("target") else ""
            out.append(f"```{pc.get('dsl', 'sqlite')}{tgt}")
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
            out.append(yaml.safe_dump({k: cfg[k] for k in cfg if k != "body"}, sort_keys=False).strip())
            out.append("```")
        elif ntype == "checkpoint":
            op = "if~:" if cfg.get("fuzzy") else "if:"
            out.append(f"{op} `{cfg.get('condition', '')}`")
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
        kids = children.get(nid, [])
        if ntype == "checkpoint":
            for cid, branch in kids:
                out.append(f"{_branch_kw.get(branch or 'default', 'then')}: → {cid}")
        else:
            for cid, _ in kids:
                out.append(f"→ {cid}")
        if not kids:
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


def validate_markdown(text: str, *, profile: str = "huntbase") -> list[Issue]:
    """Lint a hunt.md against the format + a runtime profile ('huntbase' | 'format')."""
    issues: list[Issue] = []
    try:
        pb = parse_markdown(text)
    except ConversionError as exc:
        return [Issue("error", "", str(exc))]

    slugs = {s.slug for s in pb.steps}
    severity = pb.meta.get("severity")
    if isinstance(severity, str) and severity not in _SEVERITY_ORDINAL:
        issues.append(Issue("warn", "", f"severity '{severity}' not in {sorted(_SEVERITY_ORDINAL)}"))

    # edges reference existing nodes
    for e in pb.edges:
        if e.to not in slugs:
            issues.append(Issue("error", e.frm, f"edge → '{e.to}' targets an unknown step"))

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
        if s.kind == "action":
            gated = s.attrs.get("approval") == "required"
            if not gated:
                issues.append(Issue("warn", s.slug, "action is not gated (approval: required)"))
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
    return issues


def _runtime_vars(s: Step) -> list[str]:
    vals: list[str] = []
    for k in ("in", "out", "context"):
        v = s.attrs.get(k)
        if isinstance(v, list):
            vals += [str(x) for x in v if str(x).startswith("$")]
    return vals


def _is_root_ok(step: Step, pb: Playbook) -> bool:
    """A step with no incoming edge is fine if it's a parallel branch entry or the first step."""
    if pb.steps and pb.steps[0].slug == step.slug:
        return True
    for s in pb.steps:
        if s.kind == "parallel" and step.slug in s.branches:
            return True
    return False
