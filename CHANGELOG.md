# Changelog

## 0.7 — 2026-09-08 (draft)

Every change is additive. A 0.6 hunt validates under 0.7 tooling with the same
errors and the same warnings under `--profile format` and `--profile huntbase`
(info-level notes may appear; they never affect the exit code), and a 0.7 hunt
read by 0.6 tooling keeps every new key as unknown frontmatter or attributes.
`tools/tests/check.py` asserts both against frozen copies of the 0.6 hunts.

### Format (SPEC)

- **§5.7 Prevalence and baseline** — `prevalence: {key, by, rare_below}` and
  `baseline: {window, compare}`: the stack-count-and-compare pattern. A runtime
  capable of native first-seen or prior-window calculation executes them
  directly; others run the query as written. Both travel as named
  `primitive_config` keys. Quality profile warns when no query declares
  prevalence or aggregates.
- **§3.7 Typed parameters and indicator provenance** — `type:` supports scalar
  primitives (`string`, `duration`, `cidr`, `regex`, etc.) and typed lists
  `list[<member>]` (`list[domain]`, `list[ip]`, `list[url]`, `list[hash]`,
  `list[path]`). Volatile indicator lists declare `from: {kind, ref, observed}`.
  Quality profile warns on volatile indicators observed over 365 days ago.
- **§5.8 Query role and paired portable form** — `role=` info-string attribute
  (`scoping`, `baseline`, `enrichment`, `triage`, `detection-candidate`). A
  secondary fenced code block flagged `portable` (`sigma`, `yara`, `yara-l`,
  `stix`, `suricata`, `snort`) attaches as the query's portable twin rather than
  redefining the step. `hunt.handoff: promote-to-detection` without a
  `detection-candidate` query is an info note by default and a warning under
  `quality`.
- **§3.8 Related hunts and series** — `series: {slug, index, total, title}` for
  multi-part investigation chains, and `related: [{hunt, relation, reason}]`
  (`precedes`, `follows`, `sibling`, `alternative`, `supersedes`,
  `superseded-by`, `out-of-scope-alternative`). CLI `--split -o <dir>` splits
  multi-hypothesis MISP events into series-wired hunt files.
- **§8.2 Agent context budget and citation demand** — `context:` entries accept
  `{step, rows}` objects to bound evidence input tokens alongside bare step
  names; `cite: required | optional` states explicit citation demands at the
  step level.
- **MISP hygiene (#11)** — Stricter `is_misp_event` shape verification prevents
  non-event YAML/JSON from being misidentified. CLI `--date` argument (or
  `created:` frontmatter) pins the event date for reproducible, byte-stable
  fixtures. `misp-galaxy:mitre-attack-pattern` tags emitted from named ATT&CK
  references; `workflow:state` mirrors context status; sigma logsource target
  derivation replaces SIEM guesses; multi-event restSearch responses parsed and
  split cleanly.

### Tooling

- **Backward compatibility promise (0.6 → 0.7):** Frozen copies of the 0.6 repo
  hunts added under `tools/tests/fixtures/*-0.6.md`; `check.py` asserts they lint
  with identical errors and warnings under `format` and `huntbase` profiles.
  Handoff promotion check is info-level under default profiles and warned only
  under `quality`.
- **JSON & CACAO export serialization:** CLI `convert` passes `default=str` to
  `json.dumps` for `--to cacao` and `--to json` so `datetime.date` objects
  parsed from YAML frontmatter and parameter declarations serialize without
  `TypeError`.
- **CLI `--date` flag:** Wired through `_cmd_convert` to `markdown_to_misp`,
  enabling deterministic exports for fixtures and CI.
- **Portable rule export/import:** In MISP, portable twins export as standard
  `sigma`/`yara` objects linked `tests` → hypothesis and `derived-from` → the
  query step; re-import restores them as twins on the corresponding step. In
  CACAO, twins ride in `x_hunt_portable`.
- **Quality profile additions:** Warns on stale indicator lists (>365 days) and
  on hunts lacking any prevalence or aggregation steps.

### Verified

- `tools/tests/check.py`: All 90+ regression assertions passing, including
  frozen 0.5 and 0.6 backward compatibility, CLI `--date` pinning, CACAO/JSON
  serialization across all repository hunts, and multi-hypothesis event splitting.
- Full profile validation matrix (`format`, `huntbase`, `misp`, `quality`, and
  `--max-tlp green`) clean across all repository hunts.

### Hunts

- `hunts/adcs-esc1-certificate-abuse.md`: Added out-of-scope alternative under
  `related:`, context budget with `cite: required` on triage, Sigma portable
  twin with `role=detection-candidate`, and prevalence stack-count.
- `hunts/kerberoasting.md`: Added prevalence stack-count.
- `hunts/scattered-spider-identity-takeover.md`: Added typed `list[path]` parameter
  with advisory provenance, Sigma portable twin with `role=detection-candidate`,
  and prevalence stack-count.
- `tools/tests/fixtures/`: Added frozen 0.6 versions of all three hunts.

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

### Verified

- `tools/tests/e2e_misp.py` against a live MISP 2.5.45 (misp-docker, taxonomy
  v4 and `threat-hunt-*` v1 installed): every repo hunt pushes, all objects,
  attributes, references and tags are stored, the re-fetched event re-imports
  byte-exact, the objects-only draft carries `hunt:`, target telemetry and
  `provenance.source`, the §12.3 outcome/handoff/period land, and `restSearch`
  by `hunt-ex:trigger` / `handoff` / `telemetry` / `outcome` finds the right
  hunts. A second run takes the `/events/edit` path. The script now covers
  every file in `hunts/` and asserts the 0.6 additions.

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
