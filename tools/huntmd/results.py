"""Run results — validate what a hunt.md execution emits (SPEC §12).

A hunt says what to do; a *result* records what happened. Without a defined
shape, two runtimes executing the same hunt produce output nobody can compare,
audit, or hand to an analyst — and an agent's conclusion can't be separated from
its evidence.

The rules enforced here are the ones with teeth (SPEC §12.2):

* a `benign` disposition needs supporting evidence, not merely an absence of
  malicious evidence;
* telemetry that wasn't examined is reported, never treated as benign;
* an explanation without a citation is not a finding.

Everything else is vocabulary checking, which exists so results aggregate.
"""

from __future__ import annotations

from typing import Any

from huntmd.core import Issue

#: Closed vocabularies (SPEC §12.1). Free text doesn't aggregate.
ANSWER_STATUS = ("matched", "not_matched", "partial", "unknown", "not_applicable")
ASSESSMENT = ("malicious", "suspicious", "potentially_benign", "benign", "inconclusive")
CONFIDENCE = ("high", "medium", "low")

_BENIGN_DISPOSITIONS = ("benign", "potentially_benign")


def is_result_document(doc: Any) -> bool:
    """True for a run result, so callers can tell one from a hunt or a playbook."""
    return isinstance(doc, dict) and isinstance(doc.get("hunt_result"), dict)


def validate_result(doc: Any, *, citations_required: bool = True) -> list[Issue]:
    """Lint a run-result document. Returns errors and warnings, same as a hunt."""
    if not is_result_document(doc):
        return [Issue("error", "", "not a run result (expected a top-level 'hunt_result' mapping)")]
    result = doc["hunt_result"]
    issues: list[Issue] = []

    for field in ("hunt", "disposition"):
        if not result.get(field):
            issues.append(Issue("error", "", f"hunt_result.{field} is required"))
    if not result.get("run"):
        issues.append(Issue("warn", "", "hunt_result.run is unset — results can't be told apart across runs"))

    disposition = str(result.get("disposition") or "")
    if disposition and disposition not in ASSESSMENT:
        issues.append(Issue("error", "", f"disposition '{disposition}' not in {list(ASSESSMENT)}"))
    confidence = result.get("confidence")
    if confidence is not None and str(confidence) not in CONFIDENCE:
        issues.append(Issue("error", "", f"confidence '{confidence}' not in {list(CONFIDENCE)}"))

    summary = result.get("evidence_summary") or {}
    if not isinstance(summary, dict):
        issues.append(Issue("error", "", "evidence_summary must be a mapping"))
        summary = {}

    # §12.2(1) — benign is a claim, and a claim needs support.
    if disposition in _BENIGN_DISPOSITIONS and not (summary.get("benign_supporting") or []):
        issues.append(
            Issue(
                "error",
                "",
                f"disposition '{disposition}' with no evidence_summary.benign_supporting — "
                "a benign verdict requires a supported explanation, not an absence of malicious evidence",
            )
        )

    steps = result.get("step_results") or []
    if not isinstance(steps, list):
        issues.append(Issue("error", "", "step_results must be a list"))
        steps = []

    coverage = result.get("telemetry_coverage") or {}
    missing = coverage.get("missing") or [] if isinstance(coverage, dict) else []
    for entry in missing if isinstance(missing, list) else []:
        if isinstance(entry, dict) and not entry.get("impact"):
            issues.append(
                Issue(
                    "warn",
                    str(entry.get("target") or ""),
                    "missing telemetry with no 'impact' — record what could not be determined without it",
                )
            )

    saw_unexamined = False
    for step in steps:
        if not isinstance(step, dict):
            issues.append(Issue("error", "", "each step_results entry must be a mapping"))
            continue
        slug = str(step.get("step") or "")
        if not slug:
            issues.append(Issue("error", "", "step_results entry has no 'step'"))

        status = str(step.get("answer_status") or "")
        if not status:
            issues.append(Issue("error", slug, "answer_status is required"))
        elif status not in ANSWER_STATUS:
            issues.append(Issue("error", slug, f"answer_status '{status}' not in {list(ANSWER_STATUS)}"))
        if status == "not_applicable":
            saw_unexamined = True

        assessment = step.get("assessment")
        if assessment is not None and str(assessment) not in ASSESSMENT:
            issues.append(Issue("error", slug, f"assessment '{assessment}' not in {list(ASSESSMENT)}"))

        # §12.2(3) — an explanation without a citation is an assertion.
        if citations_required and step.get("explanation") and not (step.get("evidence") or []):
            issues.append(
                Issue(
                    "error",
                    slug,
                    "explanation with no evidence citation (guardrail evidence: citation_required)",
                )
            )
        # §12.2(2) — a step that couldn't be examined must not read as a finding.
        if status == "not_applicable" and str(assessment or "") in _BENIGN_DISPOSITIONS:
            issues.append(
                Issue(
                    "error",
                    slug,
                    f"answer_status 'not_applicable' with assessment '{assessment}' — "
                    "unexamined telemetry is not evidence of benignity",
                )
            )

    if saw_unexamined and not missing:
        issues.append(
            Issue(
                "warn",
                "",
                "a step reported 'not_applicable' but telemetry_coverage.missing is empty — "
                "record which source was unavailable",
            )
        )
    return issues
