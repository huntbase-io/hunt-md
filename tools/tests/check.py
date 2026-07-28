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

Exits non-zero on the first failing group, printing what differed.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from huntmd.cacao import cacao_to_markdown, markdown_to_cacao  # noqa: E402
from huntmd.core import (  # noqa: E402
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

print()
if failures:
    print(f"FAILED: {len(failures)} check(s) — {', '.join(failures[:5])}")
    raise SystemExit(1)
print("All checks passed.")
