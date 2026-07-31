# huntmd — reference converter & validator

Reference tooling for the [`hunt.md`](../SPEC.md) format: convert a `.md` hunt to
a Huntbase playbook **definition** (and back), and lint it. Self-contained —
stdlib + PyYAML only.

## Install / run

```bash
# one-off (from this directory)
pip install pyyaml
python -m huntmd validate ../hunts/kerberoasting.md

# or install the CLI
pip install -e .
huntmd convert ../hunts/kerberoasting.md
```

## Usage

```bash
# hunt.md → Huntbase definition (YAML on stdout; use --to json for JSON)
huntmd convert  hunts/my-hunt.md
huntmd convert  hunts/my-hunt.md --to json -o my-hunt.definition.json

# Huntbase definition (.yaml/.json) → hunt.md
huntmd convert  my-hunt.definition.yaml

# hunt.md → CACAO v2 playbook JSON (interchange export)
huntmd convert  hunts/my-hunt.md --to cacao
huntmd convert  hunts/my-hunt.md --to cacao -o my-hunt.cacao.json

# CACAO playbook (v1.x or v2.0) → hunt.md; the input format is detected by shape
huntmd convert  some-playbook.json -o hunts/imported.md

# lint against a profile (default: huntbase; 'format' = neutral spec; 'cacao' = interchange)
huntmd validate hunts/my-hunt.md
huntmd validate hunts/my-hunt.md --profile format

# refuse to publish anything above a sharing level (public repos use green)
huntmd validate hunts/my-hunt.md --max-tlp green

# lint a run result (SPEC §12) — detected by its `hunt_result` root
huntmd validate results/2026-07-31-kerberoasting.yaml
```

`validate` exits non-zero if there are **errors** (warnings don't fail). It
reports unreachable steps, missing query targets, ungated actions, unbounded
agent steps, fuzzy conditions with no `indeterminate:` branch, and — for the
`huntbase` profile — constructs the runtime can't execute (`while:`,
sub-playbook `run:`, `switch:`, runtime `$var` dataflow) with the substitution
it will apply. The `cacao` profile adds no restrictions of its own: every
construct exports, so a hunt clean at `format` level is clean for interchange.

It also enforces the v0.5 safety rules: guardrail keys and values (SPEC §8.1),
a warning on any guardrail relaxed from its default, a warning on numeric `if~:`
confidence (prefer ordinal), and an error when `unavailable: → end` would close a
hunt on telemetry it never examined.

For a **run result**, it checks the controlled vocabularies plus the three rules
with teeth (SPEC §12.2): a `benign` disposition needs supporting evidence, an
explanation needs a citation, and an unexamined step can't be assessed benign.

## What it targets

**Huntbase definition** (default) — `{"hunt": {...}, "nodes": [{"id","type",`
`"config"|"primitive_config","parents":[...]}]}`, node types
`query | collection | action | checkpoint | task | analytic`. Covers the
Huntbase-profile subset (see [`../PROFILES.md`](../PROFILES.md)).

**CACAO v2** (`--to cacao`) — a complete OASIS CACAO Security Playbooks v2.0
playbook: `workflow` steps (`action`, `if-condition`, `switch-condition`,
`while-condition`, `parallel`, `playbook-action`) bracketed by `start`/`end`,
plus `playbook_variables`, `agent_definitions`, `target_definitions` and
`external_references`. Hunt semantics ride in the extensions `x-org-query`,
`x-org-agent-directive`, `x-org-fuzzy-condition`, `x-org-ai-agent` and `x-hunt`
(hypothesis, ATT&CK techniques, data requirements, determinism label).

Identifiers are **deterministic** — `uuid5` over the playbook id plus
`kind:slug` (SPEC §10) — so re-exporting an unchanged hunt is byte-identical
apart from `created`/`modified`. Pin those via frontmatter to get a fully
reproducible artifact.

Both are reference implementations, not the only possible ones — another runtime
would write its own adapter over the same parsed graph.

## Scope / limitations (v0.1)
- Parses the constructs in [`../SPEC.md`](../SPEC.md): frontmatter, query/collect/
  agent/manual/action blocks, `if:`/`if~:`/`switch:`, `parallel/join`, `→` jumps,
  `###` inline groups, launch parameters, targets.
- `definition → hunt.md` is best-effort (targets and some control-flow nuance
  aren't fully reconstructed). `hunt.md → definition` is the primary path.
- **A CACAO import is a draft.** hunt.md → CACAO → hunt.md is exact, but a
  *foreign* playbook has no hypothesis, ATT&CK labels or abstract targets to
  recover — CACAO has nowhere to carry them. The importer emits `TODO` markers so
  `validate` points at what an author must supply. Verified against 49 real
  playbooks from six projects (see [`../examples/cacao-import/`](../examples/cacao-import)).
- CACAO output is structurally complete but **not schema-validated** against the
  OASIS spec by this tool — run it through a CACAO validator before publishing.
- Not yet: full multi-step parallel-branch tails, `while:`/sub-playbook execution
  (rejected by the huntbase profile).

## Layout
| File | |
|---|---|
| `huntmd/core.py` | parser, IR, Huntbase definition emitter (+ inverse), IR → markdown, linter |
| `huntmd/cacao.py` | CACAO v2 export **and** CACAO v1.x/v2.0 import, over the same IR |
| `huntmd/results.py` | run-result vocabularies + validation (SPEC §12) |
| `huntmd/__main__.py` | CLI |
