# hunt.md — runtime & interchange profiles

The `hunt.md` format (see `SPEC.md`) is vendor-neutral. A **profile** is an
adapter between the format's IR and a specific runtime or interchange target,
plus a **capability matrix** stating what that target supports. Authors target a
profile; the linter reports what a hunt needs vs. what the profile provides.

Nothing here changes the format — a hunt.md file is the same file regardless of
profile. Profiles only decide how it *renders elsewhere* and *what runs*.

---

## How the layers relate

The three profiles are not competitors — they're different jobs, and a hunt
passes through all of them:

```
hunt.md            →   runtime profile      →   interchange profile
(author · review        (Huntbase: run it)       (CACAO v2: share it)
 · diff · render)
   the source            the execution             the wire format
```

`hunt.md` is the **source of truth**: the artifact a human writes, a reviewer
diffs in a PR, and version control signs. A runtime profile is where it
*executes*. An interchange profile is how it *travels* between organizations.
Asking which is "better" is asking whether source code is better than a build
artifact — they're different stages of the same pipeline, and hunt.md is the
stage humans work at.

---

## Capability matrix (at a glance)

Two different questions, so two different legends. **Execution** (does it
actually run?) is the Huntbase and docs-only columns. **Expression** (does the
construct survive the trip?) is the CACAO column — CACAO is a transport format,
so nothing "runs" there by design; the SOAR platform on the far side decides
that.

| Format construct | hunt.md (source) | Huntbase (executes) | CACAO v2 (exports) | Docs-only |
|---|---|---|---|---|
| `query` step | ✍️ one fenced block | ✅ runs on connectors | 📦 `x-org-query` * | 📄 rendered |
| `collection` step | ✍️ ` ```collect ` | ✅ runs | 📦 command | 📄 |
| `agent` step | ✍️ ` ```agent ` | ✅ runs (an agent) | 📦 `x-org-agent-directive` * | 📄 |
| `decision` `if:` | ✍️ `if:` + `then/else` | ✅ | 📦 `if-condition` | 📄 |
| `decision` `if~:` (fuzzy) | ✍️ `if~:` | ✅ agent-judged | 📦 `x-org-fuzzy-condition` * | 📄 |
| `decision` `switch:` | ✍️ case list | ⚠️ chained binary | 📦 `switch-condition` | 📄 |
| `task` (human) | ✍️ ` ```manual ` | ✅ | 📦 `manual` | 📄 |
| `action` (change) | ✍️ ` ```action ` | ✅ approval-gated | 📦 action step | 📄 |
| `parallel` / `join` | ✍️ `parallel:`/`join:` | ✅ | 📦 `parallel` | 📄 |
| launch `parameters` (`{{}}`) | ✍️ frontmatter | ✅ | 📦 `playbook_variables` | 📄 |
| runtime dataflow (`$var`) | ✍️ `out=`/`in=` | ⚠️ entity/session-scoping | 📦 `__var__` | ❌ |
| `loop` (`while:`) | ✍️ `while:` | 🛣️ use bounded agent iteration | 📦 `while-condition` | ❌ |
| `subplaybook` (`run:`) | ✍️ `run:` | 🛣️ launch sub-hunts separately | 📦 `playbook-action` | ❌ |
| **hypothesis** | ✍️ frontmatter | ✅ first-class | 📦 `x-hunt` * | 📄 |
| **ATT&CK techniques** | ✍️ `labels:` | ✅ first-class | 📦 `x-hunt` * | 📄 |
| **data requirements** | ✍️ derived from `targets:` | ✅ pre-launch check | 📦 `x-hunt` * | 📄 |
| **human review / diff** | ✅ plain-text PR | — | — | ✅ |

✍️ native syntax · ✅ executes natively · ⚠️ executes via a documented substitution ·
🛣️ not executed today; linted with a documented alternative (roadmap) ·
📦 exports losslessly · 📄 rendered as text · ❌ not applicable ·
`*` carried as a CACAO extension (see §2)

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
properties rather than being dropped. Export is one-way today — the `.md` stays
authoritative. Signing applies to the compiled CACAO artifact; the source is
signed by version control.

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
