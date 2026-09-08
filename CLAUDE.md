# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

This is a **format specification repo**, not an application. It defines `hunt.md` — an open, vendor-neutral Markdown format for threat-hunting playbooks — plus a hunt library and a reference Python implementation.

The specification is the product. [SPEC.md](SPEC.md) is normative; everything else follows it. When spec and code disagree, the spec wins unless the user says otherwise — and a spec change should be reflected in the tooling, the template, and the example hunts in the same change.

## Commands

Tooling lives in [tools/](tools/) (Python ≥3.10, stdlib + PyYAML only — keep it dependency-free so it can be vendored into a runtime's import path).

```bash
cd tools
pip install -e .                                        # or: pip install pyyaml

python -m huntmd validate ../hunts/kerberoasting.md                 # lint (huntbase profile, default)
python -m huntmd validate ../hunts/kerberoasting.md --profile format # lint against the neutral spec only
python -m huntmd convert  ../hunts/kerberoasting.md                 # hunt.md → Huntbase definition YAML
python -m huntmd convert  ../hunts/kerberoasting.md --to cacao      # hunt.md → CACAO v2 playbook JSON
python -m huntmd convert  ../my-hunt.definition.yaml                # definition → hunt.md (best-effort inverse)
python -m huntmd convert  ../some-cacao-playbook.json               # CACAO → hunt.md (draft, TODO-marked)
python -m huntmd convert  ../hunts/kerberoasting.md --to misp       # hunt.md → MISP event JSON (HUNT-EX tags + threat-hunt-* objects)
python -m huntmd convert  ../hunts/kerberoasting.md --to misp --result ../examples/results/kerberoasting-run.yaml  # + threat-hunt-finding
python -m huntmd convert  ../some-misp-event.json                   # MISP → hunt.md (exact via attachment, else draft)
python -m huntmd validate ../hunts/kerberoasting.md --profile misp  # HUNT-EX classifiability warnings
python -m huntmd validate ../hunts/kerberoasting.md --profile quality  # opt-in "more than a rule" checks (PROFILES §5)
python -m huntmd validate ../hunts/kerberoasting.md --max-tlp green  # publication gate (public repo policy)
python -m huntmd validate ../examples/results/run.yaml               # lint a run result (SPEC §12)
```

`validate` exits non-zero only on **errors**; warnings pass. Conversion direction is inferred from file extension and *shape* (`Event`/`info`+`Object` ⇒ MISP event, `nodes` ⇒ Huntbase definition, `workflow` ⇒ CACAO), not a flag.

CI ([.github/workflows/lint.yml](.github/workflows/lint.yml)) runs the checks below on every PR, and a separate job enforces the publication boundary (`--max-tlp green` — this repo is public). After touching `core.py`, `cacao.py`, `misp.py` or `results.py`:

1. `validate` + `convert` (all three targets) over every file in [hunts/](hunts/).
   **Compatibility rule:** a 0.5 hunt must lint with the same errors and warnings after your change — `check.py` asserts this against frozen copies in [tools/tests/fixtures/](tools/tests/fixtures/). New checks on 0.5-valid content are `info`, or live in `--profile quality`.
2. **Round-trip must stay exact** for repo hunts: `md → cacao → md` preserves step kinds, slugs, targets, parameters and every edge. This is load-bearing — it's what the CACAO profile claims in [PROFILES.md](PROFILES.md).
3. `python tools/tests/check.py` — the actual suite (stdlib only). Covers all of the above plus guardrails, confidence/`unavailable:` handling, result validation, and MISP (`md → misp → md` byte-exact via the attachment; objects-only events import as lint-clean drafts).
4. **Live MISP check** (opt-in, needs an instance): `MISP_URL=… MISP_KEY=… python tools/tests/e2e_misp.py` — pushes both hunts, re-imports byte-exact, checks templates/taxonomy presence and `hunt-ex` tag search. Run it after touching `misp.py`'s object shapes; MISP drops malformed/unknown-template objects *silently*, so unit tests can't catch that class of bug.
5. **Corpus check**: [examples/cacao-import/fetch-corpus.sh](examples/cacao-import/fetch-corpus.sh) pulls 49 real CACAO playbooks from six projects; all must import, parse and lint clean (332 steps preserved). Requires `gh` + network. The vendored conversions in [examples/cacao-import/](examples/cacao-import/) are the offline fixtures.

## Architecture

### Three layers, kept separate on purpose

1. **Format** ([SPEC.md](SPEC.md)) — the IR and Markdown syntax. Vendor-neutral by rule: no product, agent, or model may be named in the core format.
2. **Profiles** ([PROFILES.md](PROFILES.md)) — adapters from the IR to a runtime (Huntbase), interchange/sharing targets (CACAO v2, MISP/HUNT-EX), or docs-only. Platform specifics belong **here, never in SPEC.md**. The capability matrix at the top of PROFILES.md is the contract: ✅ native / ⚠️ documented substitution / ❌ lint-and-reject.
3. **Reference implementation** ([tools/huntmd/](tools/huntmd/)) — adapters over the parsed graph: `core.py` for the Huntbase definition, `cacao.py` for CACAO v2, `misp.py` for MISP events (all both directions).

### The pipeline in `tools/huntmd/core.py` (single ~650-line module)

```
hunt.md text
  → _split_frontmatter / _iter_sections / _parse_section   (per-## section → Step)
  → _wire_edges                                            (document order + → jumps + then/else/indeterminate + parallel/join)
  → Playbook{name, description, meta, steps[], edges[]}    (the IR — everything hangs off this)
       ├→ playbook_to_definition   (IR → Huntbase {"hunt", "nodes":[…]})
       ├→ playbook_to_cacao        (IR → CACAO v2)          [cacao.py]
       ├→ playbook_to_misp         (IR [+ run result] → MISP event) [misp.py]
       ├→ playbook_to_markdown     (IR → hunt.md source)    ← used by both importers
       └→ validate_markdown        (IR → list[Issue])
  cacao_to_playbook / misp_to_playbook / definition_to_markdown are the inbound halves.
```

Adding another interchange format means writing `X_to_playbook` / `playbook_to_X` against the IR — never touching the parser.

Key invariants when editing:

- **A second fence in one section is a redefinition unless flagged `portable`.** `_parse_section` replaces the step's language/body on every fence, which is 0.5 behaviour and stays. A fence whose info-string carries the bare flag `portable` attaches as `step.portable` instead (SPEC §5.8). Bare info-string flags parse to `True`.
- **Step kind is inferred, not declared.** A section's kind comes from its content — fenced block language (`agent`/`manual`/`action`/`collect` in `_BLOCK_LANG_KIND`, any other language ⇒ `query`) or an `if:`/`if~:`/`switch:`/`while:`/`run:`/`parallel:` clause. An explicit override is a heading suffix: `## triage [agent]`.
- **Edges live on the target node.** The Huntbase definition puts edges in each node's `parents: [{id, branch, kind}]`, not as a separate edge list. `branch` maps `on_true|on_false|default` → `on_supports|on_refutes|default`.
- **Three fidelity tiers (SPEC §2).** Tier 1 native Markdown, Tier 2 `~~~yaml` attribute blocks (parsed by `_extract_inner_yaml`), Tier 3 raw ` ```hunt-json `. A decompiler must prefer Tier 1, spill to Tier 2, fall back to Tier 3, and **never drop data** — preserve unknown keys through both directions.
- **`{{param}}` vs `$var`.** `{{name}}` is a launch-time parameter (portable, substituted via `params=(qname=source)` in the info string); `$name` is runtime dataflow between steps (`out=`/`in=`). Queries stay parameterized — never inline values into query text.
- **Two DSL sets.** `_KNOWN_DSLS` (format-level; unknown ⇒ warn, never reject) is a superset of `_HUNTBASE_DSLS` (what the runtime can execute). Unknown language is a lint, not a format error.
- **`x_hunt_*` extension keys are the round-trip's load-bearing parts.** CACAO collapses distinctions hunt.md makes — task vs action are both `manual` commands, query vs collection both `x-org-query`, and step slugs aren't recoverable from display names. `x_hunt_kind`, `x_hunt_slug`, `x_hunt_role` and `x_hunt_type` carry them across. Drop one and the round-trip silently degrades (an `action` returns as a `task`) rather than failing loudly.
- **Guardrails are default-on and always materialised.** `effective_guardrails()` resolves document → step overrides against `_GUARDRAIL_DEFAULTS`, and `_hunt_meta`/`x_hunt` always emit the resolved set even when the author wrote no block — a runtime must never have to infer the safety posture. Relaxations warn rather than error: legal, but conspicuous in review.
- **`indeterminate:` vs `unavailable:` is a real distinction, not a synonym.** The first means examined-but-undecided, the second means never examined. `unavailable: → end` is a lint error under the default `missing_data: not_benign`, because that's the shape of a hunt quietly concluding "benign" on data nobody looked at. The Huntbase node graph collapses both to `default`; CACAO keeps them apart via `on_unavailable`.
- **MISP objects can't hold the graph, so the source rides along.** `playbook_to_misp` emits `threat-hunt-context/hypothesis/query[/finding]` + `hunt-ex:*` tags *and* the full `.md` as an `attachment` attribute. `misp_to_markdown` returns that attachment byte-exact when present and only builds a TODO-marked draft from the objects when it isn't. Classification (`trigger`, `methodology`, `applicability`, `handoff`) is read from the neutral `hunt:` block and telemetry from the targets (SPEC §3.3, §6); the legacy `misp:` keys are honoured with an info notice. `misp:` holds only MISP-only knobs. Vocabularies live in `core.HUNT_EX_VOCAB` (taxonomy v4) and `_TEMPLATES` (objects v1); bump them together with the upstream.
- **Exporters never drop unknown data.** `_hunt_meta` whitelists the first-class keys and puts everything else in `x_hunt_frontmatter`; each node carries `x_hunt_attrs`; CACAO does the same via `x_hunt.frontmatter` / step `x_hunt_attrs`. `check.py`'s passthrough fingerprint fails if a new key is lost — when you add a first-class key, add it to `_DEFINITION_META_KEYS` / `_CACAO_NATIVE_FRONTMATTER` *and* to the importer, or leave it to the passthrough.
- **Confidence is ordinal.** `Step.confidence` is `str | float`; ordinal is preferred and numeric warns. Don't "improve" this by normalising to a float — the point is that model-reported numeric confidence isn't calibrated.
- **Arrow suppression depends on in-degree.** `playbook_to_markdown` omits a `→` when the successor is simply the next step in the document, but only if that successor has exactly one parent. A join or jump target needs its edge written out, or reparsing won't rebuild it (`_wire_edges` skips document-order edges into explicitly-targeted steps).

### Linter rules (`validate_markdown`)

Format-level: edges resolve, queries have `target=`, `if~:` has an `indeterminate:` branch (error), agent steps have `tools` + `max_iterations` (warn), actions are `approval: required` (warn), reachability, severity ordinal, guardrail vocabulary (error) and relaxation (warn), numeric confidence (warn), `unavailable: → end` (error).
Run results are a separate entry point: `results.py::validate_result`, reached by `validate` when the input has a `hunt_result` root.
Format-level, 0.7: parameter types and indicator `from:` (§3.7), `prevalence`/`baseline` shape (§5.7), `role` vocab, portable-block language, `handoff: promote-to-detection` with no `detection-candidate` (§5.8).
Format-level, 0.6: `hunt:` vocab (§3.3), `scenario`/`coverage` structure (§3.4 — stage without coverage and unresolved `covered` steps are errors), `blind_spots` ids and references (§3.5 — dangling reference is an error), query contract vocab and `verified: none` on `tlp: clear` (§5.5), `silence:` closes-on-silence (§5.6), target telemetry planes (§6), `provenance` shape (§3.6). All warn except where noted.
Huntbase-profile-only: `while:` and `run:` are errors; `switch:` and `$var` dataflow are warnings naming the documented substitution. Keep profile-specific checks behind the `profile == "huntbase"` branch so `--profile format` stays neutral.
MISP-profile-only (`misp.py::misp_issues`): info-level "moved" notices for legacy `misp:` classification keys, off-vocabulary legacy values, query language with no `hunt-ex:query-language` mapping, no target that maps to a telemetry plane, no ATT&CK label.
Quality-profile-only (`core.py::_quality_issues`, opt-in, all warnings): indicator-list queries, converging fuzzy branches, containment verbs in `manual` prose, `max_iterations` below context count, references without url, no `hunt.justification`, `unavailable:` without a blind spot, <2 covered stages, stale `verified_at`. The repo hunts must pass it (check.py enforces).

## Authoring hunts

New hunts: copy [templates/hunt-template.md](templates/hunt-template.md) into [hunts/](hunts/), named `<kebab-slug>.md`. One hypothesis per file; split multi-hypothesis work into separate files. Cite `references`. Include at least one `attack.tXXXX` label. Prefer abstract `targets` (`category:`) with optional namespaced bindings (`huntbase: { product: … }`) over hard-coding a product. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rule list — it mirrors the linter, so update both together.
