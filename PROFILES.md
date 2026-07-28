# hunt.md — runtime & interchange profiles

The `hunt.md` format (see `SPEC.md`) is vendor-neutral. A **profile** is an
adapter between the format's IR and a specific runtime or interchange target,
plus a **capability matrix** stating what that target supports. Authors target a
profile; the linter reports what a hunt needs vs. what the profile provides.

Nothing here changes the format — a hunt.md file is the same file regardless of
profile. Profiles only decide how it *renders elsewhere* and *what runs*.

---

## Capability matrix (at a glance)

| Format construct | Huntbase (runtime) | CACAO v2 (export) | Generic / docs-only |
|---|---|---|---|
| `query` step | ✅ executes (connectors) | ✅ `x-org-query` command | 📄 rendered |
| `collection` step | ✅ executes | ✅ command | 📄 |
| `agent` step | ✅ executes (an agent) | ✅ `x-org-agent-directive` | 📄 |
| `decision` `if:` | ✅ | ✅ `if-condition` | 📄 |
| `decision` `if~:` (fuzzy) | ✅ (agent-judged) | ✅ `x-org-fuzzy-condition` | 📄 |
| `decision` `switch:` | ⚠️ chained binary | ✅ `switch-condition` | 📄 |
| `task` (human) | ✅ | ✅ `manual` | 📄 |
| `action` (change) | ✅ approval-gated | ✅ action step | 📄 |
| `parallel` / `join` | ✅ | ✅ `parallel` | 📄 |
| launch `parameters` (`{{}}`) | ✅ | ✅ `playbook_variables` | 📄 |
| runtime dataflow (`$var out/in`) | ⚠️ entity/session-scoping | ✅ `__var__` | ❌ |
| `loop` (`while:`) | ❌ (agent `max_iterations` only) | ✅ `while-condition` | ❌ |
| `subplaybook` (`run:`) | ❌ (launch separately) | ✅ `playbook-action` | ❌ |

✅ native · ⚠️ supported with a documented substitution · ❌ not supported (lint) · 📄 rendered as text (no execution)

> The matrix is the point of "supported, not a limit": Huntbase executes most of
> the format today; the few ⚠️/❌ cells are *runtime* gaps, not *format* limits —
> the same file still round-trips and exports to CACAO, and those gaps are on the
> Huntbase roadmap.

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

**Documented substitutions (⚠️).**
- **Runtime `$var` dataflow** → Huntbase v1 has launch params + session/entity
  scoping, not named runtime binding. An agent step extracts entities; downstream
  queries are session-scoped to them. The importer lints `in/out=$var` and
  applies this fallback.
- **`switch:`** → compiled to chained binary `checkpoint`s.

**Unsupported (❌, lint & reject):** `while:` loops and inline `subplaybook`
execution. (Use bounded `agent` iteration; launch sub-hunts separately.)

**Import path.** `POST /playbooks` accepting `text/markdown`; export via the
inverse serializer (round-trip with `derive()`).

---

## 2. CACAO v2 profile (interchange export)

One-way export from the IR to OASIS CACAO Security Playbooks v2 JSON, for
STIX/TAXII sharing and SOAR consumption. This is the profile the original
"CACAO-MD" draft was written against; here it's *an* adapter, not the core.

- steps → CACAO workflow steps (`action`, `if-condition`, `switch-condition`,
  `while-condition`, `parallel`, `playbook-action`).
- queries → `x-org-query` extension command (carries `query_language`, `query`,
  `params`).
- `agent` → `x-org-agent-directive` command + `x-org-ai-agent` agent definition.
- `if~:` → `if-condition` + `x-org-fuzzy-condition` extension (`predicate, judge,
  confidence_threshold, on_indeterminate`).
- targets → `agent_definitions` / `target_definitions`.
- hunt metadata (hypothesis, ATT&CK techniques, data requirements) → an `x-hunt`
  playbook extension — what makes a CACAO library queryable as a *hunt* catalog.

Export is **lossy-forward** where CACAO can't express a hunt.md construct
(rare); those spill into extension properties. Signing applies to the compiled
CACAO artifact, not the markdown (VCS signs the source).

---

## 3. Generic / docs-only profile (no runtime)

A hunt.md is valuable with **zero tooling**: it renders as a readable document
and serves as high-quality context for AI coding/analysis assistants (Claude
Code, Copilot, Cursor) and knowledge bases. No execution, no connectors —
queries and steps are read, not run. This is the on-ramp: a hunt authored here
is immediately useful, and gains execution the moment it's imported into a
runtime profile.

---

## Adding a profile
A new runtime implements: (1) IR-kind → its step model, (2) target resolution,
(3) parameter/variable handling, (4) a capability declaration for the matrix,
(5) a linter pass. Keep platform specifics here — never in `SPEC.md`.
