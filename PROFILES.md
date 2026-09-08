# hunt.md — runtime & interchange profiles

The `hunt.md` format (see `SPEC.md`) is vendor-neutral. A **profile** is an
adapter between the format's IR and a specific runtime or interchange target,
plus a **capability matrix** stating what that target supports. Authors target a
profile; the linter reports what a hunt needs vs. what the profile provides.

Nothing here changes the format — a hunt.md file is the same file regardless of
profile. Profiles only decide how it *renders elsewhere* and *what runs*.

---

## How the layers relate

The profiles are not competitors — they're different jobs, and a hunt passes
through all of them:

```
hunt.md            →   runtime profile      →   interchange profiles
(author · review        (Huntbase: run it)       (CACAO v2: ship the playbook)
 · diff · render)                                 (MISP: share the hunt)
   the source            the execution             the wire formats
```

`hunt.md` is the **source of truth**: the artifact a human writes, a reviewer
diffs in a PR, and version control signs. A runtime profile is where it
*executes*. An interchange profile is how it *travels* between organizations — CACAO
carries the *executable playbook* to a SOAR, MISP carries the *hunt as
intelligence* (hypothesis, queries, findings, HUNT-EX classification) to a
sharing community. Asking which is "better" is asking whether source code is better than a build
artifact — they're different stages of the same pipeline, and hunt.md is the
stage humans work at.

---

## Capability matrix (at a glance)

Two different questions, so two different legends. **Execution** (does it
actually run?) is the Huntbase and docs-only columns. **Expression** (does the
construct survive the trip?) is the CACAO and MISP columns — both are transport
formats, so nothing "runs" there by design; the platform on the far side decides
that. MISP is the coarser of the two on purpose: its objects describe *what the
hunt is and found*, not *how it flows* — so the full source rides along as an
attachment (†) and the objects hold what HUNT-EX makes searchable.

| Format construct | hunt.md (source) | Huntbase (executes) | CACAO v2 (interchange) | MISP / HUNT-EX (sharing) | Docs-only |
|---|---|---|---|---|---|
| `query` step | ✍️ one fenced block | ✅ runs on connectors | 📦 `x-org-query` * | 📦 `threat-hunt-query` | 📄 rendered |
| `collection` step | ✍️ ` ```collect ` | ✅ runs | 📦 command | † | 📄 |
| `agent` step | ✍️ ` ```agent ` | ✅ runs (an agent) | 📦 `x-org-agent-directive` * | † (summarised in `analysis`) | 📄 |
| `decision` `if:` | ✍️ `if:` + `then/else` | ✅ | 📦 `if-condition` | † | 📄 |
| `decision` `if~:` (fuzzy) | ✍️ `if~:` | ✅ agent-judged | 📦 `x-org-fuzzy-condition` * | † | 📄 |
| `decision` `switch:` | ✍️ case list | ⚠️ chained binary | 📦 `switch-condition` | † | 📄 |
| `task` (human) | ✍️ ` ```manual ` | ✅ | 📦 `manual` | † | 📄 |
| `action` (change) | ✍️ ` ```action ` | ✅ approval-gated | 📦 action step | † | 📄 |
| `parallel` / `join` | ✍️ `parallel:`/`join:` | ✅ | 📦 `parallel` | † | 📄 |
| launch `parameters` (`{{}}`) | ✍️ frontmatter | ✅ | 📦 `playbook_variables` | † (noted in query `comment`) | 📄 |
| runtime dataflow (`$var`) | ✍️ `out=`/`in=` | ⚠️ entity/session-scoping | 📦 `__var__` | † | ❌ |
| `loop` (`while:`) | ✍️ `while:` | 🛣️ use bounded agent iteration | 📦 `while-condition` | † | ❌ |
| `subplaybook` (`run:`) | ✍️ `run:` | 🛣️ launch sub-hunts separately | 📦 `playbook-action` | † | ❌ |
| **guardrails** (§8.1) | ✍️ frontmatter, default-on | ✅ enforced | 📦 `x-hunt.guardrails` * | † | ❌ |
| `unavailable:` branch | ✍️ `unavailable:` | ⚠️ routed as indeterminate | 📦 `on_unavailable` * | † | 📄 |
| ordinal confidence | ✍️ `confidence: high` | ✅ | 📦 `x-org-fuzzy-condition` * | † | 📄 |
| **run results** (§12) | ✍️ emitted, not authored | ✅ emits | ❌ no CACAO equivalent | 📦 `threat-hunt-finding` + `hunt-ex:outcome` | ❌ |
| **hypothesis** | ✍️ frontmatter | ✅ first-class | 📦 `x-hunt` * | 📦 `threat-hunt-hypothesis` | 📄 |
| **ATT&CK techniques** | ✍️ `labels:` | ✅ first-class | 📦 `x-hunt` * | 📦 `attack-id` on the hypothesis | 📄 |
| **data requirements** | ✍️ derived from `targets:` | ✅ pre-launch check | 📦 `x-hunt` * | 📦 `data-source`/`tool` + `hunt-ex:telemetry` | 📄 |
| **unknown keys / attrs** (§2) | ✍️ any frontmatter key, any `~~~yaml` attr | 📦 `x_hunt_frontmatter` / `x_hunt_attrs` | 📦 `x-hunt.frontmatter` / `x_hunt_attrs` * | † | 📄 |
| **human review / diff** | ✅ plain-text PR | — | — | — | ✅ |

✍️ native syntax · ✅ executes natively · ⚠️ executes via a documented substitution ·
🛣️ not executed today; linted with a documented alternative (roadmap) ·
📦 exports losslessly · 📄 rendered as text · ❌ not applicable ·
`*` carried as a CACAO extension (see §2) ·
`†` not a MISP object; carried by the attached hunt.md source (see §3)

**Reading the matrix.** hunt.md's column is full because the format was designed
around what hunts actually contain — a hypothesis, ATT&CK coverage, data
requirements, and hybrid deterministic/agentic steps. The bottom four rows are
the ones to look at: those are hunt-native concepts, and they're the reason the
format exists rather than being a thin skin over an existing playbook standard.

Nothing is lost travelling downstream: every construct either executes, executes
via a documented substitution, or exports intact. The ⚠️/🛣️ cells are *runtime
scope* on the Huntbase roadmap — never format limits and never data loss. A hunt
using a construct its runtime can't execute still renders, still round-trips
byte-stably, and still exports in full; the linter says so explicitly rather than
silently mis-compiling it.

---

## 1. Huntbase profile (executing runtime)

Imports a hunt.md as a **Huntbase hunt playbook** (Playbooks v2): the IR maps to
the playbook `definition` (`{"hunt", "nodes":[…]}`) that the platform
materializes and launches.

**Step kind → node type**

| IR kind | Huntbase node type |
|---|---|
| query | `query` (`primitive_config: {query_language, content, parameter_values}`) |
| collection | `collection` |
| agent | `analytic` (a platform agent — **Scout is one such agent**; the runtime binds it) |
| decision (`if`/`if~`) | `checkpoint` (`if~` also emits an `analytic` verdict node) |
| task | `task` |
| action | `action` (`action_approval`) |
| edges / branch | node `parents: [{id, branch: on_supports\|on_refutes\|default, kind}]` |

**Targets → connections.** An abstract `category` (or a `huntbase: {product: …}`
binding hint) resolves to the tenant's connections; the referenced set becomes
`required_product_slugs` for the compatibility check. Query `query_language` must
map to a supported DSL (`kql, spl, esql, esdsl, aql, mysql, osquery, sqlite,
cypher, stix`); others lint.

**Parameters.** `parameters:` → playbook parameters; `params=(q=name)` + `{{q}}`
is the native substitution.

**Agents are generic here too.** `target: { agent: true }` binds to whatever
agent the tenant runs for that step (Scout by default). The format never assumes
Scout; Huntbase just happens to ship one.

**Guardrails (§8.1).** A profile must state whether it *enforces* the safety
posture or merely records it — claiming a property you don't enforce is worse
than declaring the gap. Huntbase enforces `telemetry: untrusted` (tool output is
passed as data, never merged into the agent's instructions) and
`missing_data: not_benign` (a step whose source is unavailable routes the
`unavailable:` branch rather than falling through). `evidence:
citation_required` and `claims: no_unsupported` are enforced at result
validation (§12) rather than during execution.

**Documented substitutions (⚠️).**
- **Runtime `$var` dataflow** → Huntbase v1 has launch params + session/entity
  scoping, not named runtime binding. An agent step extracts entities; downstream
  queries are session-scoped to them. The importer lints `in/out=$var` and
  applies this fallback.
- **`switch:`** → compiled to chained binary `checkpoint`s.
- **`unavailable:`** → the node graph carries one `default` branch, so an
  `unavailable:` edge is materialised as `default` alongside `indeterminate:`.
  The distinction survives in the step config and in run results, but the runtime
  routes both to the same successor unless they already differ.

**Unsupported (❌, lint & reject):** `while:` loops and inline `subplaybook`
execution. (Use bounded `agent` iteration; launch sub-hunts separately.)

**Import path.** `POST /playbooks` accepting `text/markdown`; export via the
inverse serializer (round-trip with `derive()`).

---

## 2. CACAO v2 profile (interchange)

**CACAO is the standard we export to, and we're glad it exists.** OASIS CACAO
Security Playbooks v2 is the right answer to "how do playbooks move between
organizations and SOAR platforms" — it's well-specified, STIX/TAXII-native, and
signable. hunt.md doesn't compete with it; hunt.md is the **authoring layer above
it**. You write the hunt in Markdown, review it in a PR, and compile it to CACAO
when it's time to ship.

That division of labour is the point. CACAO JSON is an excellent *machine*
interchange format and a poor thing to hand-write or code-review: a hunt is
hundreds of lines of nested objects with UUID cross-references, where a
one-character diff is unreadable. hunt.md gives that same graph a human surface —
and then hands CACAO a complete, valid artifact.

**Mapping.** The IR lines up cleanly with CACAO's workflow model:

- steps → CACAO workflow steps (`action`, `if-condition`, `switch-condition`,
  `while-condition`, `parallel`, `playbook-action`).
- queries → `x-org-query` extension command (carries `query_language`, `query`,
  `params`).
- `agent` → `x-org-agent-directive` command + `x-org-ai-agent` agent definition.
- `if~:` → `if-condition` + `x-org-fuzzy-condition` extension (`predicate, judge,
  confidence_threshold, on_indeterminate`).
- targets → `agent_definitions` / `target_definitions`.
- hunt metadata (hypothesis, ATT&CK techniques, data requirements) → an `x-hunt`
  playbook extension — what makes a CACAO library queryable as a *hunt* catalog
  rather than a flat pile of playbooks.

**On the extensions.** Queries, agent steps, fuzzy conditions, and hunt metadata
travel as CACAO *extensions* (`x-org-*`, `x-hunt`) — which is exactly the
mechanism CACAO defines for domain-specific semantics, used as intended. It does
mean the hunt-specific meaning lives in the extension payload: a generic CACAO
consumer runs the workflow skeleton, while a hunt-aware consumer gets the
hypothesis, the ATT&CK coverage, and the agent directives. Keeping hunt.md as the
source of truth is what preserves that richer meaning for everyone downstream.

**Fidelity.** Export is lossless for the constructs above and **lossy-forward**
only where CACAO has no native concept (rare); those spill into extension
properties rather than being dropped. Signing applies to the compiled CACAO
artifact; the source is signed by version control.

**Producing it.** Implemented in [`tools/huntmd/cacao.py`](./tools/huntmd/cacao.py):

```bash
huntmd convert hunts/kerberoasting.md --to cacao -o kerberoasting.cacao.json
huntmd validate hunts/kerberoasting.md --profile cacao
```

The exporter brackets the workflow in CACAO `start`/`end` steps, maps
`parameters:` to external `playbook_variables` (`{{lookback}}` → `__lookback__`)
and `$var` dataflow to internal ones, resolves `targets:` into
`agent_definitions` / `target_definitions`, and emits ATT&CK labels as
`external_references` alongside the `x-hunt` extension. Identifiers are
deterministic (`uuid5` over the playbook id + `kind:slug`, SPEC §10), so an
unchanged hunt re-exports byte-identically apart from its timestamps.

Two structural notes, since CACAO's graph model differs slightly from the IR's:
a `then:`/`else:` arm pointing at `end` is implicit in hunt.md but explicit in
CACAO (it resolves to the end step), and a non-decision step that fans out to
several successors gets a synthetic `parallel` step, because a CACAO `action`
has only one `on_completion`.

### Import (CACAO → hunt.md)

The reverse direction works too — `huntmd convert playbook.json` detects a CACAO
playbook by shape and emits hunt.md. It accepts **CACAO 2.0 and 1.x** (the older
`single` step type), all workflow step types, and the command types that appear
in practice (`ssh`, `bash`, `powershell`, `http-api`, `openc2`, `manual`,
`attack-cmd`, …). Step kinds are recovered from command types: `x-org-query` →
`query`, `x-org-agent-directive` → `agent`, `manual` → `task`, anything that
changes state → `action` (SPEC §9). Original step ids are pinned in Tier-2
blocks, and the three variable conventions found in the wild (`__x__`, `$$x$$`,
bare) all normalise to `{{x}}`.

**An import is a draft, not a hunt.** A foreign playbook carries no hypothesis,
no ATT&CK labels and no abstract `targets:`, because CACAO has nowhere to put
them. The importer emits `TODO` markers for each, so `huntmd validate` points
straight at what an author still has to supply. The `.md` is the source of truth
from that point on; regenerate the CACAO artifact rather than editing it.

**Round-trip.** `md → CACAO → md` is exact for hunt.md-authored files — step
kinds, slugs (including `###` group paths), targets, parameters and every edge
survive, because the exporter carries what CACAO can't natively express
(`x_hunt_kind`, `x_hunt_slug`, `x_hunt_role`, `x_hunt_type`) in extension
properties. `CACAO → md → CACAO` preserves every step and its wiring; what it
cannot invent is the hunt metadata the source never had.

**Tested against real playbooks.** The importer was developed against a corpus of
**49 CACAO playbooks from six independent projects** — every one converts to a
hunt.md that parses and lints clean, with all 332 steps preserved. Reference
conversions and a script that reproduces the corpus are in
[`examples/cacao-import/`](./examples/cacao-import).

---

## 3. MISP profile (sharing — HUNT-EX taxonomy + `threat-hunt-*` objects)

**MISP is where a hunt goes to be *found* by peers.** MISP now ships the
[HUNT-EX taxonomy](https://github.com/MISP/misp-taxonomies/tree/main/hunt-ex)
and four companion objects — `threat-hunt-context`, `threat-hunt-hypothesis`,
`threat-hunt-query`, `threat-hunt-finding` — so a hunt can be shared as a
structured, queryable artefact instead of a free-text report or a pile of IOCs.
An analyst at a peer organisation filters for
`hunt-ex:telemetry="identity"` + `hunt-ex:query-language="kusto"` and gets every
hunt in the community they have the telemetry to reproduce.

hunt.md and HUNT-EX are complementary and were designed for different moments:
HUNT-EX classifies a hunt *at the point of sharing*; hunt.md is the *source* the
hunt was authored and executed from. So this profile is two things at once — the
searchable objects and tags MISP wants, and the exact source alongside them.

**Mapping.**

| hunt.md | MISP |
|---|---|
| frontmatter `name`, H1 description, `targets:` (data sources + `product` bindings) | `threat-hunt-context` — `hunt-title`, `purpose`, `data-source`, `tool`, `methodology`, `status` |
| `hypothesis:` + `attack.tXXXX` labels | `threat-hunt-hypothesis` — `hypothesis`, `attack-id`, `hypothesis-id: H1`, `analysis` (a one-line-per-step summary of the flow), `status` |
| every `query` step | one `threat-hunt-query` — `query`, `query-language`, `data-source` (the target), `platform` (its binding), `comment` (params + description); linked `tests` → the hypothesis |
| a run result (SPEC §12), via `--result` | `threat-hunt-finding` — `outcome`, `conclusion` (disposition, per-step explanations, evidence summary, unexamined telemetry), `recommendation`; linked `concludes` → the hypothesis |
| `tlp:` | `tlp:*` event tag (and MISP `distribution`) |
| `severity:` | `threat_level_id` |
| `references:` | `link` attributes |
| **the whole file** | an `attachment` attribute `<slug>.hunt.md` — the exact source (†) |

**Tags.** The event carries `hunt-ex:content="hypothesis"` (+ `"query"`, +
`"finding"` when a result is exported), `hunt-ex:query-language=` for each
query language used (hunt.md `kql` → `kusto`, `stix` → `stix-pattern`, SQL
dialects → `sql`, unknown → `other`), `hunt-ex:telemetry=` derived from target
planes (SPEC §6: declared `telemetry:` on a store, or derived from a plane
category — `siem` is a store, not a plane, so it contributes nothing on its
own), and `hunt-ex:methodology=` (default `structured-hypothesis-driven`,
since a hunt.md always has a hypothesis).

The classification HUNT-EX asks for is read from the neutral `hunt:` block
(SPEC §3.3) — `trigger`, `methodology`, `applicability`, `handoff` — and the
telemetry planes from the targets (SPEC §6), so a hunt classifies for sharing
without any MISP-specific content. What remains in the optional, namespaced
`misp:` block is genuinely MISP-only — the same convention as `huntbase:`
bindings on targets, and just as ignorable by every other profile:

```yaml
misp:
  contributors: [ISAC hunt team]
  tags: ['workflow:state="complete"']   # any extra event tags, verbatim
  distribution: 2                # MISP distribution; defaults from tlp
  purpose: …                     # context.purpose, when the H1 description isn't it
```

*Deprecated in 0.6, still honoured:* `misp.trigger` / `methodology` /
`applicability` / `handoff` (now `hunt.*`) and `misp.telemetry` (now
`targets.<slug>.telemetry`). The exporter reads the new home first, the old one
second, and `--profile misp` prints an info-level "moved" notice for each. They
are removed in a later minor version.

`huntmd validate --profile misp` warns when a legacy `misp:` value is
off-vocabulary, when a query language has no HUNT-EX mapping, when no target
maps to a telemetry plane, or when there is no ATT&CK label — each is something
a peer would filter on and fail to find.

**Findings and outcomes.** A run result that records `outcome`, `byproducts`,
`handoff` and `period` (SPEC §12.3) exports them as-is: `hunt-ex:outcome=`,
one `hunt-ex:byproduct=` per entry, `hunt-ex:handoff=`, and
`period-start`/`period-end` on the context object. Without a recorded
`outcome`, the exporter falls back to a conservative mapping from
`disposition` and says so in the finding's `conclusion`: `malicious` →
`hypothesis-confirmed-malicious`; `benign`/`potentially_benign` →
`hypothesis-confirmed-benign` (a `benign` with no `benign_supporting` evidence
— invalid under §12.2 anyway — degrades to `hypothesis-not-confirmed`);
`suspicious` and `inconclusive` → `inconclusive`, because "suspicious" is
precisely *not* a confirmed hypothesis. Any `telemetry_coverage.missing` entry
adds `hunt-ex:byproduct="data-source-gap"` whether or not it was listed — the
hunt has told you what it couldn't look at, and that is worth sharing.

**Producing it.** Implemented in [`tools/huntmd/misp.py`](./tools/huntmd/misp.py):

```bash
huntmd convert hunts/kerberoasting.md --to misp -o kerberoasting.misp.json
huntmd convert hunts/kerberoasting.md --to misp --result examples/results/kerberoasting-run.yaml
huntmd validate hunts/kerberoasting.md --profile misp
```

The output is a standard MISP event JSON (`{"Event": {…}}`) that `PyMISP`,
`misp-import` or the REST API accept as-is. Identifiers are `uuid5`-derived from
the playbook id (SPEC §10), so re-exporting an unchanged hunt is stable, and an
event can be updated in place. Object templates are pinned to
`threat-hunt-*` v1; the taxonomy vocabularies to `hunt-ex` v4.

**Verified against a live MISP** (2.5.44 via misp-docker) —
[`tools/tests/e2e_misp.py`](./tools/tests/e2e_misp.py) pushes every repo hunt,
fetches it back as MISP serialises it, re-imports it byte-exact, and confirms
`restSearch` by `hunt-ex:telemetry` + `hunt-ex:query-language` finds them. What
that surfaced, so you don't rediscover it:

- **The instance must have the `threat-hunt-*` templates and `hunt-ex`
  taxonomy.** They were merged upstream recently; images built before that
  (2.5.44's bundle, for one) don't have them, and MISP **silently drops** any
  object whose template it doesn't know — the event saves, tags and attachment
  land, and the objects just aren't there. Run
  `cake Admin updateObjectTemplates` / `updateTaxonomies` (or update the
  `misp-objects` / `misp-taxonomies` submodules) and *enable* the `hunt-ex`
  taxonomy first. The e2e script checks for this before pushing.
- **Re-export ⇒ `POST /events/edit/<uuid>`, not `add`.** Ids are deterministic,
  so a second `add` is a duplicate. Under `edit`, single-valued attributes
  (`status`, `hypothesis`, `query`, …) have value-independent ids and are
  *replaced*; only relations that legitimately repeat (`data-source`, `tool`,
  `contributor`, `attack-id`) key on their value.
- **Deleting an event blocklists its UUID.** With deterministic ids that means a
  deleted hunt can't be re-pushed until the entry is removed from
  `/eventBlocklists`. Prefer `edit`, or unpublish, over delete.
- MISP requires a non-empty object `description` (the template's own is
  emitted) and de-duplicates identical attribute values within an object.

### Import (MISP → hunt.md)

`huntmd convert event.json` recognises a MISP event by shape and:

- if the event carries the `<slug>.hunt.md` attachment, returns that source
  **byte-exact** — `md → MISP → md` round-trips completely, control flow and all;
- otherwise (an event authored by a peer, or with the attachment stripped) builds
  a **draft**: one `query` step per `threat-hunt-query` (plus any `sigma`/`yara`
  objects in the event), `hypothesis:` and `attack.*` labels from the hypothesis
  object, `tlp:` from the tag, targets from the queries' `data-source`s, and a
  `threat-hunt-finding` as a `manual` review step so a re-run is compared against
  what the peer found. HUNT-EX classification tags land in `hunt:`, telemetry
  tags on the targets, and the event UUID in `provenance.source` (SPEC §3.6);
  `contributor`, `rationale` and `analysis` come back as `provenance.authors`,
  `rationale:` and `analysis:`. Everything the objects can't say — decisions, agent steps,
  target categories — is `TODO`-marked, and the draft lints clean so
  `huntmd validate` points at exactly what an author still owes.

An event with several `threat-hunt-hypothesis` objects imports the first and
lists the rest under a `TODO` — hunt.md is one hypothesis per file.

---

## 4. Generic / docs-only profile (no runtime)

A hunt.md is valuable with **zero tooling**: it renders as a readable document
and serves as high-quality context for AI coding/analysis assistants (Claude
Code, Copilot, Cursor) and knowledge bases. No execution, no connectors —
queries and steps are read, not run. This is the on-ramp: a hunt authored here
is immediately useful, and gains execution the moment it's imported into a
runtime profile.

---

## 5. Quality profile (opt-in lint, no runtime)

`huntmd validate --profile quality` runs every format-level check plus the
rules that make a hunt more than a rule. None of them is a format error and
none runs under the default profiles, so a 0.5 hunt lints exactly as it did;
a generation pipeline, a curated library or a PR gate turns them on.

| rule | why |
|---|---|
| a query is a literal indicator list (five or more literals in one `in (…)` and nothing that stacks or baselines) — and, if *every* query is, the hunt is | indicators rot; a list with a hypothesis attached is a rule |
| an `if~:` whose branches all reach the same step | the judgement changes nothing |
| a `manual` task whose prose says *isolate / disable / delete / quarantine / revoke / wipe / terminate / reset the…* | a change to the estate should be a gated ```` ```action ```` step |
| an `agent` step whose `max_iterations` is below its `context` count | it cannot finish |
| a `references` entry with no `url` | a reviewer cannot verify the logic |
| no `hunt.justification` (SPEC §3.3) | a negative result is indefensible without it |
| an `unavailable:` branch that names no `blind_spot` (SPEC §3.5) | the dead end has no recorded cost |
| fewer than two `scenario` stages `covered` (SPEC §3.4) | a one-stage hunt is a rule |
| `verified_at` older than 180 days (SPEC §5.5) | the verification claim is folklore |
| a query target that resolves to no telemetry plane (SPEC §6) | data requirements are not checkable (an info under the default profiles) |

All warnings; the exit code is unaffected. The repository's own hunts pass it,
and `tools/tests/check.py` keeps them passing.

---

## Adding a profile
A new runtime implements: (1) IR-kind → its step model, (2) target resolution,
(3) parameter/variable handling, (4) a capability declaration for the matrix,
(5) a linter pass. Keep platform specifics here — never in `SPEC.md`. An
interchange/sharing profile is the same shape minus execution:
`X_to_playbook` / `playbook_to_X` over the IR plus a `profile == "x"` lint
branch — [`tools/huntmd/misp.py`](./tools/huntmd/misp.py) is the smallest
worked example (≈750 lines, both directions, one namespaced frontmatter block).
