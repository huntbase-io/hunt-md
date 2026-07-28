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
python -m huntmd convert  ../hunts/kerberoasting.md --to json -o out.json
python -m huntmd convert  ../my-hunt.definition.yaml                # definition → hunt.md (best-effort inverse)
```

`validate` exits non-zero only on **errors**; warnings pass. Direction is inferred from file extension/content, not a flag.

There is no test suite and no CI workflow in the repo (the README refers to CI lint that isn't wired up yet). The de-facto regression check is running `validate` and `convert` over both files in [hunts/](hunts/) — do that after any change to `core.py`, and diff the converter output before/after.

## Architecture

### Three layers, kept separate on purpose

1. **Format** ([SPEC.md](SPEC.md)) — the IR and Markdown syntax. Vendor-neutral by rule: no product, agent, or model may be named in the core format.
2. **Profiles** ([PROFILES.md](PROFILES.md)) — adapters from the IR to a runtime (Huntbase), an interchange target (CACAO v2), or docs-only. Platform specifics belong **here, never in SPEC.md**. The capability matrix at the top of PROFILES.md is the contract: ✅ native / ⚠️ documented substitution / ❌ lint-and-reject.
3. **Reference implementation** ([tools/huntmd/](tools/huntmd/)) — one adapter over the parsed graph, targeting the Huntbase profile.

### The pipeline in `tools/huntmd/core.py` (single ~650-line module)

```
hunt.md text
  → _split_frontmatter / _iter_sections / _parse_section   (per-## section → Step)
  → _wire_edges                                            (document order + → jumps + then/else/indeterminate + parallel/join)
  → Playbook{name, description, meta, steps[], edges[]}    (the IR)
  → playbook_to_definition                                 (IR → Huntbase {"hunt", "nodes":[…]})
  → definition_to_markdown                                 (inverse, best-effort)
  → validate_markdown                                      (IR → list[Issue])
```

Key invariants when editing:

- **Step kind is inferred, not declared.** A section's kind comes from its content — fenced block language (`agent`/`manual`/`action`/`collect` in `_BLOCK_LANG_KIND`, any other language ⇒ `query`) or an `if:`/`if~:`/`switch:`/`while:`/`run:`/`parallel:` clause. An explicit override is a heading suffix: `## triage [agent]`.
- **Edges live on the target node.** The Huntbase definition puts edges in each node's `parents: [{id, branch, kind}]`, not as a separate edge list. `branch` maps `on_true|on_false|default` → `on_supports|on_refutes|default`.
- **Three fidelity tiers (SPEC §2).** Tier 1 native Markdown, Tier 2 `~~~yaml` attribute blocks (parsed by `_extract_inner_yaml`), Tier 3 raw ` ```hunt-json `. A decompiler must prefer Tier 1, spill to Tier 2, fall back to Tier 3, and **never drop data** — preserve unknown keys through both directions.
- **`{{param}}` vs `$var`.** `{{name}}` is a launch-time parameter (portable, substituted via `params=(qname=source)` in the info string); `$name` is runtime dataflow between steps (`out=`/`in=`). Queries stay parameterized — never inline values into query text.
- **Two DSL sets.** `_KNOWN_DSLS` (format-level; unknown ⇒ warn, never reject) is a superset of `_HUNTBASE_DSLS` (what the runtime can execute). Unknown language is a lint, not a format error.

### Linter rules (`validate_markdown`)

Format-level: edges resolve, queries have `target=`, `if~:` has an `indeterminate:` branch (error), agent steps have `tools` + `max_iterations` (warn), actions are `approval: required` (warn), reachability, severity ordinal.
Huntbase-profile-only: `while:` and `run:` are errors; `switch:` and `$var` dataflow are warnings naming the documented substitution. Keep profile-specific checks behind the `profile == "huntbase"` branch so `--profile format` stays neutral.

## Authoring hunts

New hunts: copy [templates/hunt-template.md](templates/hunt-template.md) into [hunts/](hunts/), named `<kebab-slug>.md`. One hypothesis per file; split multi-hypothesis work into separate files. Cite `references`. Include at least one `attack.tXXXX` label. Prefer abstract `targets` (`category:`) with optional namespaced bindings (`huntbase: { product: … }`) over hard-coding a product. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rule list — it mirrors the linter, so update both together.
