# Changelog

## 0.6 — 2026-09-08 (draft)

Every change is additive. A 0.5 hunt validates under 0.6 tooling with the same
errors and the same warnings under `--profile format` and `--profile huntbase`
(info-level migration notes may appear; they never affect the exit code), and a
0.6 hunt read by 0.5 tooling keeps every new key as unknown frontmatter.
`tools/tests/check.py` asserts both against frozen copies of the 0.5 hunts.

### Format (SPEC)

- **§3.3 `hunt:` block** — `trigger`, `methodology`, `applicability`, `handoff`
  (HUNT-EX vocabularies), plus `justification`, `assets`, `review_by`: why the
  hunt exists and what happens after, in a neutral home. (#1, #3)
- **§3.4 `scenario:` + `coverage:`** — the intrusion chain a hunt was written
  from, and per stage whether it is `covered` (by which steps), `not_visible`,
  `out_of_scope` or an `existing_rule`. (pipeline proposal A)
- **§3.5 `blind_spots:`** — a dead end as a record with a cost: `requires`,
  `question`, `risk`, `owner`, `remediation`. Referenced from `coverage`
  `not_visible` entries, from `unavailable: → x (blind_spot: id)` branches, and
  from run results. (#2, proposal G)
- **§3.1 `rationale:` / `analysis:`** — prose beside the hypothesis; carried on
  the MISP hypothesis object instead of a synthesised summary. (#10)
- **§3.6 `provenance:`** — `authors`, `source {system, ref, imported}`,
  `generated {by, model, from, gates}`. (#7, proposal I)
- **§5.1 language table** — one table (`core.LANGUAGES`) feeds the linter, the
  Huntbase profile and the HUNT-EX mapping; `xql`, `cql`, `yara-l`, `suricata`,
  `shell`, `powershell`, `python`, `pseudocode`, `kusto` added; `esdsl` shares
  as `other`. (#8)
- **§5.5 verification contract** — `source`, `reads`, `verified`, `verified_at`
  on query/collection steps; named `primitive_config` keys in the Huntbase
  definition so the runtime can preflight columns. (proposal C)
- **§5.6 expected signal and silence** — `expected:` and `silence:
  not_evidence_of_absence | evidence_of_absence`; a decision that closes on
  silence its author marked as proving nothing warns. (proposal E)
- **§6 telemetry planes** — `targets.<slug>.telemetry`, derived from a plane
  category or declared on a store; a query target with no plane is an info
  note under the default profiles and a warning under `quality`. (#4)
- **§7.2** — `unavailable:` may name the blind spot it is the cost of.
- **§12.3 run results** — `outcome`, `byproducts`, `handoff`, `period`, and
  `telemetry_coverage.missing[].blind_spot`. (#5)
- **§13** — three severities (`error`, `warn`, `info`); the opt-in `quality`
  profile.

### Tooling

- **Exporters never drop unknown data.** The definition and CACAO exporters
  now carry every unknown frontmatter key and Tier-2 step attribute
  (`x_hunt_frontmatter` / `x_hunt_attrs`, `x-hunt.frontmatter`) and restore
  them on import. Previously both silently dropped them; `md → md` was the
  only lossless path. A generic passthrough fingerprint in `check.py` fails if
  a future key regresses.
- `huntmd validate --profile quality` (PROFILES §5): indicator-list queries,
  converging fuzzy branches, containment verbs in `manual` prose,
  `max_iterations` below the context count, references without a url, missing
  `hunt.justification`, `unavailable:` without a blind spot, fewer than two
  covered stages, stale `verified_at`. Warnings only; the repo hunts pass it.
- MISP export reads `hunt:` and target planes first; `misp:` classification
  keys are **deprecated but honoured** with an info-level "moved" notice.
  Import writes `hunt:`, target `telemetry`, `provenance.source`, `rationale`,
  `analysis`. A recorded `outcome` beats the disposition heuristic; the
  conclusion says which was used.
- CACAO: target keys other than `name`/`category` ride in `x_hunt_bindings`;
  internal `$var` variables no longer come back as launch parameters;
  `created_by` seeds from `provenance.authors`.
- Parser: a `~~~yaml` block may trail an agent fence (the SPEC §8.1 form);
  `else: → end` is recorded for the silence rule; action `track:` survives the
  definition round-trip.
- `Issue` gains an `info` level; only errors affect the exit code.

### Deprecated (removed no earlier than 0.8)

- `misp.trigger` / `methodology` / `applicability` / `handoff` → `hunt.*`
- `misp.telemetry` → `targets.<slug>.telemetry`
- `misp.event` (import stopgap) → `provenance.source.ref`

### Hunts

- New: `hunts/adcs-esc1-certificate-abuse.md` — the worked example for
  scenario/coverage, blind spots, the verification contract and provenance.
- All three hunts carry a `hunt:` block and telemetry planes; the Scattered
  Spider hunt records the blind spot its `unavailable:` branch is the cost of.

## 0.5

MISP / HUNT-EX profile, guardrails, `unavailable:`, run results, publication
guardrail. See git history.
