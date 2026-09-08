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
# Languages the Huntbase runtime can execute (others: portability lint), and
# the languages the open format knows — both derived from LANGUAGES below.

_SEVERITY_ORDINAL = {"critical", "high", "medium", "low"}

#: Query-language table (SPEC §5.1) — the single source the linter, the Huntbase
#: profile and the MISP exporter read. ``tag`` is the fence language; ``hunt_ex``
#: the HUNT-EX ``query-language`` value it shares as; ``huntbase`` whether that
#: runtime executes it.
LANGUAGES: tuple[tuple[str, str, bool], ...] = (
    ("kql", "kusto", True),
    ("kusto", "kusto", True),
    ("spl", "spl", True),
    ("esql", "esql", True),
    ("eql", "eql", False),
    ("esdsl", "other", True),  # Elasticsearch Query DSL: HUNT-EX has no peer; `kibana-query` is KQL-the-other-one
    ("aql", "aql", True),
    ("xql", "xql", False),
    ("cql", "cql", False),
    ("sql", "sql", False),
    ("mysql", "sql", True),
    ("sqlite", "sql", True),
    ("osquery", "sql", True),
    ("cypher", "other", True),
    ("kestrel", "other", False),
    ("sigma", "sigma", False),
    ("yara", "yara", False),
    ("yara-l", "yara-l", False),
    ("stix", "stix-pattern", True),
    ("suricata", "suricata-snort", False),
    ("snort", "suricata-snort", False),
    ("shell", "shell", False),
    ("bash", "shell", False),
    ("powershell", "powershell", False),
    ("python", "python", False),
    ("pseudocode", "pseudocode", False),
)
LANGUAGE_TO_HUNT_EX = {tag: hx for tag, hx, _ in LANGUAGES}

#: HUNT-EX vocabularies (misp-taxonomies/hunt-ex v4). The neutral ``hunt:``
#: block (SPEC §3.1) and run results (§12) use these directly, so a hunt is
#: classifiable without a MISP-specific block.
HUNT_EX_VOCAB: dict[str, tuple[str, ...]] = {
    "methodology": ("structured-hypothesis-driven", "unstructured-baseline", "model-assisted"),
    "trigger": (
        "intel-report", "sector-alert", "prior-hunt", "incident-followup", "red-team", "purple-team",
        "crown-jewel", "detection-gap", "analyst-intuition", "ioc-sweep",
    ),
    "outcome": (
        "hypothesis-confirmed-malicious", "hypothesis-confirmed-benign", "hypothesis-not-confirmed", "inconclusive",
    ),
    "byproduct": ("detection-gap", "data-source-gap", "tooling-gap", "process-gap", "vuln-or-misconfig"),
    "content": ("hypothesis", "query", "finding"),
    "telemetry": ("endpoint", "network", "identity", "email", "cloud-control-plane", "cloud-workload", "saas", "ot-ics"),
    "query-language": (
        "sigma", "yara", "suricata-snort", "stix-pattern", "spl", "kusto", "eql", "esql", "kibana-query", "aql",
        "xql", "yara-l", "cql", "devo-linq", "sql", "shell", "powershell", "python", "pseudocode", "other",
    ),
    "applicability": ("universal", "sector-specific", "environment-specific", "campaign-specific"),
    "handoff": (
        "promote-to-detection", "keep-as-periodic-hunt", "retire", "escalated-to-ir", "handed-to-detection-engineering",
    ),
}

#: The neutral ``hunt:`` frontmatter block (SPEC §3.1): programme-level facts
#: about the hunt — why it exists and what happens after — in closed vocabularies
#: shared with HUNT-EX, plus the business justification behind it.
HUNT_BLOCK_KEYS = ("trigger", "methodology", "applicability", "handoff", "justification", "assets", "review_by")
_HUNT_BLOCK_VOCAB = {k: HUNT_EX_VOCAB[k] for k in ("trigger", "methodology", "applicability", "handoff")}

#: Telemetry planes (SPEC §6) — what an organisation knows it has or lacks. A
#: target ``category`` that unambiguously names a plane derives it; a store
#: (``siem``, ``datalake``) must state ``telemetry:`` explicitly.
TELEMETRY_PLANES = HUNT_EX_VOCAB["telemetry"]
CATEGORY_TO_TELEMETRY = {
    "endpoint": "endpoint", "edr": "endpoint", "network": "network", "iam": "identity", "identity": "identity",
    "email": "email", "cloud": "cloud-control-plane", "cloud-control-plane": "cloud-control-plane",
    "cloud-workload": "cloud-workload", "saas": "saas", "ot": "ot-ics", "ics": "ot-ics", "ot-ics": "ot-ics",
}


_HUNTBASE_DSLS = {tag for tag, _, hb in LANGUAGES if hb}
_KNOWN_DSLS = {tag for tag, _, _ in LANGUAGES}


#: Scenario coverage status (SPEC §3.4): what the hunt says about each stage of
#: the intrusion chain it was written from.
COVERAGE_STATUS = ("covered", "not_visible", "out_of_scope", "existing_rule")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)


def scenario_stages(meta: dict[str, Any]) -> list[dict[str, Any]]:
    scenario = meta.get("scenario")
    stages = scenario.get("stages") if isinstance(scenario, dict) else None
    return [s for s in (stages or []) if isinstance(s, dict)] if isinstance(stages, list) else []


def hunt_block(meta: dict[str, Any]) -> dict[str, Any]:
    """The ``hunt:`` block, with the deprecated ``misp:`` keys as a fallback.

    Reads ``hunt:`` first; a classification key still living under ``misp:`` is
    honoured (one minor version of soft deprecation, see PROFILES §3) so a 0.5
    hunt classifies exactly as it did.
    """
    block = meta.get("hunt")
    out = dict(block) if isinstance(block, dict) else {}
    legacy = meta.get("misp")
    if isinstance(legacy, dict):
        for k in ("trigger", "methodology", "applicability", "handoff"):
            if k not in out and legacy.get(k) is not None:
                out[k] = legacy[k]
    return out


def target_telemetry(target: dict[str, Any]) -> list[str]:
    """Telemetry planes a data-source target covers: declared, else derived from category."""
    declared = target.get("telemetry")
    if declared:
        return [str(v) for v in ([declared] if isinstance(declared, str) else declared)]
    plane = CATEGORY_TO_TELEMETRY.get(str(target.get("category", "")).lower())
    return [plane] if plane else []


def _is_data_source(target: dict[str, Any]) -> bool:
    return not (target.get("agent") or target.get("role") or target.get("individual"))

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
    """Pull a ``~~~yaml ... ~~~`` block out of a fenced-block body.

    The block may lead the body (the common form for actions) or trail it (the
    form SPEC §8.1 shows for a per-step guardrail override on an agent step).
    """
    lines = body.splitlines()
    if lines and lines[0].strip().startswith("~~~"):
        for i in range(1, len(lines)):
            if lines[i].strip().startswith("~~~"):
                return _yaml_dict("\n".join(lines[1:i])), "\n".join(lines[i + 1 :]).strip()
    if lines and lines[-1].strip().startswith("~~~"):
        for i in range(len(lines) - 2, -1, -1):
            if lines[i].strip().startswith("~~~"):
                return _yaml_dict("\n".join(lines[i + 1 : -1])), "\n".join(lines[:i]).strip()
    return {}, body


def _yaml_dict(text: str) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


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
            rest = line.split(":", 1)[1]
            # `unavailable: → escalate-gap (blind_spot: no-ca-audit)` names the
            # §3.5 record this dead end is the cost of.
            bm = re.search(r"\(\s*blind_spot\s*:\s*([A-Za-z0-9_.-]+)\s*\)", rest)
            if bm:
                step.attrs["blind_spot"] = bm.group(1)
                rest = rest[: bm.start()] + rest[bm.end() :]
            t = _target_of(rest)
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


#: Step attributes each kind carries natively in the definition; everything else
#: rides in ``x_hunt_attrs`` so the runtime ignores it and the exporter restores
#: it (SPEC §2: spill to Tier 2, never drop).
_DEFINITION_NATIVE_ATTRS = {
    "query": {"target", "params"},
    "collection": {"target", "params"},
    "agent": {"objective", "tools", "context", "success_criteria", "max_iterations", "in", "out", "target", "params"},
    "decision": {"checkpoint_type", "target", "params"},
    "task": {"target", "params"},
    "action": {"approval", "track", "target", "params"},
}


def _extra_attrs(s: Step) -> dict[str, Any]:
    native = _DEFINITION_NATIVE_ATTRS.get(s.kind, {"target", "params"})
    return {k: v for k, v in s.attrs.items() if k not in native}


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
            extra = _extra_attrs(s)
            if extra:
                node["primitive_config"]["x_hunt_attrs"] = extra
        else:
            node["config"] = _config_for(s)
            extra = _extra_attrs(s)
            if extra:
                node["config"]["x_hunt_attrs"] = extra
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


#: Frontmatter keys the definition carries as first-class ``meta`` entries.
_DEFINITION_META_KEYS = (
    "labels", "severity", "tlp", "hypothesis", "references", "parameters", "targets", "type", "hunt", "scenario", "coverage",
    "blind_spots",
)


def _hunt_meta(pb: Playbook) -> dict[str, Any]:
    meta = {k: pb.meta[k] for k in _DEFINITION_META_KEYS if k in pb.meta}
    # Always resolved, never omitted: a runtime must receive the safety posture
    # even when the author didn't write the block (SPEC §8.1).
    meta["guardrails"] = effective_guardrails(pb.meta)
    # Everything else the author wrote travels verbatim (SPEC §2) — a profile
    # block, a key from a newer spec revision, a private extension. The runtime
    # ignores it; the exporter restores it.
    extra = {k: v for k, v in pb.meta.items() if k not in _DEFINITION_META_KEYS and k != "guardrails"}
    if extra:
        meta["x_hunt_frontmatter"] = extra
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
    "hunt",
    "scenario",
    "coverage",
    "blind_spots",
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
    "track",
    "blind_spot",
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
            if s.kind == "action":
                gate = {k: s.attrs[k] for k in ("approval", "track") if s.attrs.get(k)}
                if gate:
                    out += ["~~~yaml", _dump(gate, sort_keys=False).strip(), "~~~"]
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
                    tail = f" (blind_spot: {s.attrs['blind_spot']})" if keyword == "unavailable" and s.attrs.get("blind_spot") else ""
                    for to, br in children.get(s.slug, []):
                        if br == branch:
                            out.append(f"{keyword}: → {to}{tail}")
                if s.unavailable_to_end:
                    out.append("unavailable: → end" + (f" (blind_spot: {s.attrs['blind_spot']})" if s.attrs.get("blind_spot") else ""))
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
    passthrough = meta.pop("x_hunt_frontmatter", None)
    if isinstance(passthrough, dict):
        for k, v in passthrough.items():
            meta.setdefault(k, v)
    out: list[str] = ["---"]
    out.append(_fm_dump(meta))
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
            out.append(_dump({k: cfg[k] for k in cfg if k not in ("body", "x_hunt_attrs")}, sort_keys=False).strip())
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
            gate = {k: cfg[src] for k, src in (("approval", "action_approval"), ("track", "track")) if cfg.get(src)}
            if gate:
                out += ["~~~yaml", _dump(gate, sort_keys=False).strip(), "~~~"]
            out.append((cfg.get("instructions") or "").rstrip())
            out.append("```")
        else:  # task
            tgt = f" target={cfg['assignee']}" if cfg.get("assignee") else ""
            out.append(f"```manual{tgt}")
            out.append((cfg.get("instructions") or "").rstrip())
            out.append("```")
        # Tier-2 attributes the definition carried verbatim come back as a
        # step-level attribute block (SPEC §4.2).
        extra = (node.get("primitive_config") or {}).get("x_hunt_attrs") if ntype in ("query", "collection") else cfg.get("x_hunt_attrs")
        if isinstance(extra, dict) and extra:
            out += ["~~~yaml", _dump(extra, sort_keys=False, allow_unicode=True).strip(), "~~~"]
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
    level: str  # error | warn | info
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
    issues += _check_hunt_block(pb)
    issues += _check_telemetry(pb)
    issues += _check_scenario(pb, profile)
    issues += _check_blind_spots(pb, profile)

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


def _check_hunt_block(pb: Playbook) -> list[Issue]:
    """The neutral ``hunt:`` block (SPEC §3.1): closed vocabularies warn, never reject."""
    issues: list[Issue] = []
    block = pb.meta.get("hunt")
    if block is None:
        return issues
    if not isinstance(block, dict):
        return [Issue("error", "", "hunt: must be a mapping")]
    for key, value in block.items():
        if key not in HUNT_BLOCK_KEYS:
            issues.append(Issue("warn", "", f"hunt.{key} is not a defined key {list(HUNT_BLOCK_KEYS)} (kept verbatim)"))
            continue
        vocab = _HUNT_BLOCK_VOCAB.get(key)
        if vocab is not None:
            for v in [value] if isinstance(value, str) else (value if isinstance(value, list) else [value]):
                if str(v) not in vocab:
                    issues.append(Issue("warn", "", f"hunt.{key} '{v}' not in {list(vocab)}"))
        elif key == "assets" and not isinstance(value, list):
            issues.append(Issue("warn", "", "hunt.assets should be a list of the business assets or processes at stake"))
        elif key == "review_by" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value)):
            issues.append(Issue("warn", "", f"hunt.review_by '{value}' is not an ISO date (YYYY-MM-DD)"))
    return issues


def _check_scenario(pb: Playbook, profile: str) -> list[Issue]:
    """`scenario:` + `coverage:` (SPEC §3.4): the chain is stated, and every stage says
    whether this hunt covers it, can't see it, or chose not to."""
    issues: list[Issue] = []
    scenario = pb.meta.get("scenario")
    coverage = pb.meta.get("coverage")
    if scenario is None and coverage is None:
        return issues
    if scenario is not None and not isinstance(scenario, dict):
        return [Issue("error", "", "scenario: must be a mapping with a stages: list")]
    if coverage is not None and not isinstance(coverage, list):
        return [Issue("error", "", "coverage: must be a list of {stage, status, …} entries")]

    stages = scenario_stages(pb.meta)
    stage_slugs: list[str] = []
    for i, st in enumerate(stages):
        slug = str(st.get("slug") or "")
        if not slug:
            issues.append(Issue("error", "", f"scenario.stages[{i}] has no slug"))
            continue
        if slug in stage_slugs:
            issues.append(Issue("error", "", f"scenario stage '{slug}' is declared twice"))
        stage_slugs.append(slug)
        for tech in st.get("techniques") or []:
            if not _TECHNIQUE_ID.match(str(tech)):
                issues.append(Issue("warn", "", f"scenario stage '{slug}': technique '{tech}' is not a Txxxx[.yyy] id"))
    if scenario is not None and not stages:
        issues.append(Issue("warn", "", "scenario: has no stages — nothing for coverage: to refer to"))
    if scenario is not None and coverage is None:
        issues.append(Issue("warn", "", "scenario: without coverage: — say which stages this hunt covers, can't see, or left out"))
    if coverage is None:
        return issues
    if scenario is None:
        issues.append(Issue("warn", "", "coverage: without scenario: — the stages it names are undefined"))

    slugs = {s.slug for s in pb.steps}
    seen_stages: list[str] = []
    covered = 0
    for i, entry in enumerate(coverage):
        if not isinstance(entry, dict):
            issues.append(Issue("error", "", f"coverage[{i}] must be a mapping"))
            continue
        stage = str(entry.get("stage") or "")
        status = str(entry.get("status") or "")
        where = f"coverage[{stage or i}]"
        if not stage:
            issues.append(Issue("error", "", f"{where} has no stage"))
        elif stage_slugs and stage not in stage_slugs:
            issues.append(Issue("error", "", f"{where}: stage '{stage}' is not in scenario.stages"))
        seen_stages.append(stage)
        if status not in COVERAGE_STATUS:
            issues.append(Issue("warn", "", f"{where}: status '{status}' not in {list(COVERAGE_STATUS)}"))
        if status == "covered":
            covered += 1
            steps = entry.get("steps") or []
            if not steps:
                issues.append(Issue("error", "", f"{where}: status covered but no steps: name which steps cover it"))
            for step in steps if isinstance(steps, list) else [steps]:
                if str(step) not in slugs:
                    issues.append(Issue("error", "", f"{where}: step '{step}' does not exist"))
        elif status in ("not_visible", "out_of_scope") and not entry.get("reason"):
            issues.append(Issue("warn", "", f"{where}: status {status} with no reason — say why, or the gap is invisible"))
    for slug in stage_slugs:
        if slug not in seen_stages:
            issues.append(Issue("error", "", f"scenario stage '{slug}' has no coverage entry — covered, not_visible, out_of_scope or existing_rule?"))
    if profile == "quality" and stage_slugs and covered < 2:
        issues.append(Issue("warn", "", f"only {covered} of {len(stage_slugs)} scenario stages are covered — a one-stage hunt is a rule, not a hunt"))
    return issues


def blind_spot_ids(meta: dict[str, Any]) -> list[str]:
    spots = meta.get("blind_spots")
    return [str(b.get("id")) for b in spots if isinstance(b, dict) and b.get("id")] if isinstance(spots, list) else []


def _check_blind_spots(pb: Playbook, profile: str) -> list[Issue]:
    """`blind_spots:` (SPEC §3.5): a dead end is a record with a cost, and every
    reference to one resolves."""
    issues: list[Issue] = []
    spots = pb.meta.get("blind_spots")
    ids: list[str] = []
    if spots is not None:
        if not isinstance(spots, list):
            return [Issue("error", "", "blind_spots: must be a list of {id, requires, risk, …} entries")]
        stage_slugs = {str(s.get("slug")) for s in scenario_stages(pb.meta)}
        for i, b in enumerate(spots):
            if not isinstance(b, dict):
                issues.append(Issue("error", "", f"blind_spots[{i}] must be a mapping"))
                continue
            bid = str(b.get("id") or "")
            if not bid:
                issues.append(Issue("error", "", f"blind_spots[{i}] has no id"))
                continue
            if bid in ids:
                issues.append(Issue("error", "", f"blind spot '{bid}' is declared twice"))
            ids.append(bid)
            for key in ("requires", "risk"):
                if not b.get(key):
                    issues.append(Issue("warn", "", f"blind spot '{bid}' has no {key}: — say what is missing and what it costs"))
            if b.get("stage") and stage_slugs and str(b["stage"]) not in stage_slugs:
                issues.append(Issue("error", "", f"blind spot '{bid}': stage '{b['stage']}' is not in scenario.stages"))
    # References: coverage entries and unavailable: branches.
    for entry in pb.meta.get("coverage") or []:
        if isinstance(entry, dict) and entry.get("blind_spot") and str(entry["blind_spot"]) not in ids:
            issues.append(Issue("error", "", f"coverage[{entry.get('stage')}]: blind_spot '{entry['blind_spot']}' is not declared in blind_spots:"))
    for s in pb.steps:
        ref = s.attrs.get("blind_spot")
        if ref and str(ref) not in ids:
            issues.append(Issue("error", s.slug, f"blind_spot '{ref}' is not declared in blind_spots:"))
        if profile == "quality" and s.kind == "decision" and s.fuzzy and not ref:
            routes_unavailable = s.unavailable_to_end or any(e.frm == s.slug and e.branch == "on_unavailable" for e in pb.edges)
            if routes_unavailable:
                issues.append(Issue("warn", s.slug, "unavailable: branch with no (blind_spot: …) — the dead end has no recorded cost"))
    return issues


def _check_telemetry(pb: Playbook) -> list[Issue]:
    """Every data-source target a query reads should resolve to a telemetry plane (SPEC §6)."""
    issues: list[Issue] = []
    targets = pb.meta.get("targets") or {}
    for slug, t in targets.items():
        if not isinstance(t, dict) or not _is_data_source(t):
            continue
        for plane in target_telemetry(t):
            if plane not in TELEMETRY_PLANES:
                issues.append(Issue("warn", "", f"target {slug}: telemetry '{plane}' not in {list(TELEMETRY_PLANES)}"))
    unresolved = sorted(
        {s.target for s in pb.steps if s.kind in ("query", "collection") and s.target
         and isinstance(targets.get(s.target), dict) and _is_data_source(targets[s.target])
         and not target_telemetry(targets[s.target])}
    )
    for slug in unresolved:
        issues.append(
            Issue(
                "warn",
                "",
                f"target {slug}: category '{targets[slug].get('category')}' names a store, not a telemetry plane — "
                f"add telemetry: [{'|'.join(TELEMETRY_PLANES)}] so data requirements are checkable",
            )
        )
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
