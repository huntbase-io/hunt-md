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

# lint against a runtime profile (default: huntbase; or 'format' for the neutral spec)
huntmd validate hunts/my-hunt.md
huntmd validate hunts/my-hunt.md --profile format
```

`validate` exits non-zero if there are **errors** (warnings don't fail). It
reports unreachable steps, missing query targets, ungated actions, unbounded
agent steps, fuzzy conditions with no `indeterminate:` branch, and — for the
`huntbase` profile — constructs the runtime can't execute (`while:`,
sub-playbook `run:`, `switch:`, runtime `$var` dataflow) with the substitution
it will apply.

## What it targets

The converter emits the Huntbase playbook definition
(`{"hunt": {...}, "nodes": [{"id","type","config"|"primitive_config","parents":[...]}]}`,
node types `query | collection | action | checkpoint | task | analytic`). It
covers the Huntbase-profile subset (see [`../PROFILES.md`](../PROFILES.md)); it is
a reference implementation, not the only possible one — a different runtime would
write its own adapter over the same parsed graph.

## Scope / limitations (v0.1)
- Parses the constructs in [`../SPEC.md`](../SPEC.md): frontmatter, query/collect/
  agent/manual/action blocks, `if:`/`if~:`/`switch:`, `parallel/join`, `→` jumps,
  `###` inline groups, launch parameters, targets.
- `definition → hunt.md` is best-effort (targets and some control-flow nuance
  aren't fully reconstructed). `hunt.md → definition` is the primary path.
- Not yet: full multi-step parallel-branch tails, `while:`/sub-playbook execution
  (rejected by the huntbase profile), CACAO export (see `../PROFILES.md`).
