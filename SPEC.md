# hunt.md — specification

**Version:** 0.4 (draft) · **Status:** Working proposal
**License of this document:** see `LICENSE`

`hunt.md` is an **open, portable, human-first Markdown format for threat-hunting
playbooks**. A `.md` file describes a hunt as a typed graph of steps — queries,
data collection, agent reasoning, decisions, human tasks, and actions — that a
compliant runtime can render, review, and (if it supports execution) run.

The format is **vendor-neutral**. It defines its own small object model (the
IR). Runtimes and interchange targets are reached through **adapters** — see
`PROFILES.md` for the Huntbase runtime, CACAO v2 export, and a minimal
docs-only profile. No single platform's capabilities constrain the format;
instead, each runtime declares a **capability profile**, and a linter checks a
hunt against the profile it's targeting.

---

## 1. Design principles

1. **Portable first.** The format is not tied to any product. Query languages,
   agents, and data sources are open — a hunt authored for one stack renders
   and diffs anywhere, and runs anywhere that has the connectors.
2. **Human-readable, git-native.** Plain Markdown + YAML frontmatter. Reviewable
   in a PR, renderable in any viewer, editable without tooling.
3. **Deterministic *and* agentic are first-class.** "Run this exact query on this
   source" and "an agent should investigate X" are both native constructs —
   because real hunts are hybrid.
4. **Agent-neutral.** A step may delegate to *an* agent. The format never names a
   specific agent/vendor/model in its core; the runtime binds which agent runs.
5. **Capability profiles, not lowest-common-denominator.** The format stays
   expressive (runtime dataflow, branching, loops, sub-playbooks). Each runtime
   publishes what it supports; the linter reports what a given hunt needs.
6. **Lossless round-trip.** `md → IR → md` is stable; `IR → md → IR` is
   semantically equal. Nothing is silently dropped (§2).

---

## 2. Fidelity model (round-trip contract)

| Tier | Syntax | Coverage |
|---|---|---|
| 1 **Native** | dedicated markdown | the ~90% of constructs hunts use (§4–§9) |
| 2 **Annotated** | `~~~yaml` blocks on any element | any object property without dedicated syntax (timeouts, owner, references, platform hints…) |
| 3 **Raw** | fenced ` ```hunt-json ` blocks | anything else — preserved verbatim |

A decompiler MUST emit Tier‑1 where possible, spill unknown properties into
Tier‑2, fall back to Tier‑3, and never drop data.

---

## 3. Document structure

```
YAML frontmatter   → playbook metadata + parameters + targets
# Title            → playbook name
prose              → description / hypothesis
## step-name       → one step per section, in document order
### sub-step       → optional inline grouping (§7.1)
```

### 3.1 Frontmatter

```yaml
---
# id/version are written back by a compiler on first run (§10).
type: investigation                 # playbook_type (free string; "investigation" typical)
name: Kerberoasting hunt            # optional; falls back to the H1
labels:                             # attack.tXXXX[.YYY] → ATT&CK techniques; others → tags
  - hunt
  - attack.t1558.003
severity: high                      # critical | high | medium | low  (or 0–100; §3.2)
tlp: amber
hypothesis: >
  Service accounts are being kerberoasted from non-admin workstations.
references:
  - name: CISA AA23-320A
    url: https://www.cisa.gov/...
parameters:                         # launch-time inputs; portable {{name}} placeholders
  lookback:  { type: duration, default: "14d" }
  suspects:  { type: string }       # no default → collected at launch or bound at runtime
targets:                            # abstract data sources / agents / people (§6)
  siem:   { category: siem,      name: SIEM }
  edr:    { category: endpoint,  name: EDR }
  hunter: { agent: true,         name: Hunt agent }     # generic agent — runtime binds it
  tier2:  { role: analyst,       name: Tier-2 analyst }
---
```

Unknown frontmatter keys pass through (Tier 2). `parameters`, `targets`,
`labels`, `severity`, `hypothesis` have defined meaning (§11).

### 3.2 Severity
Prefer the ordinal words `critical | high | medium | low`. A numeric `severity`
(0–100, CACAO-style) is accepted; runtimes that are ordinal bucket it
(`≥80 critical, ≥50 high, ≥20 medium, else low`).

---

## 4. Steps and step kinds

Each `##` heading is one step; the heading text is its **slug** (stable
identity; the step id is derived from it, §10). The compiler infers the **kind**
from the section's content; an explicit override is a heading suffix
`## triage [agent]`.

| Section contains | Step kind | Meaning |
|---|---|---|
| a query block (§5) | `query` | run a query against a data source |
| a ` ```collect ` block (§5.4) | `collection` | run a data-collection primitive (pack/sweep) |
| an ` ```agent ` block (§8) | `agent` | delegate reasoning to an agent |
| an `if:` / `if~:` / `switch:` clause (§7) | `decision` | branch on a condition |
| a `while:` clause (§7.4) | `loop` | repeat until a condition holds |
| a ` ```manual ` block (§9) | `task` | a human task assigned to a role/person |
| a ` ```action ` block (§9) | `action` | a change/response (containment, remediation) |
| a `run:` clause (§7.5) | `subplaybook` | invoke another hunt.md |
| a `parallel:` / `join:` clause (§6) | *(graph only)* | concurrency — edges, not a step |

Runtimes that lack a kind reject it (or degrade) per their profile — they never
silently mis-run it.

### 4.1 Flow (edges)
Document order is the default sequence. An explicit jump overrides it:
`→ close-benign` (`->` accepted). Branches use `then:`/`else:`/`indeterminate:`
(§7). `→ end` marks a terminal step. Start/end steps are implicit (graph
roots/leaves).

### 4.2 Step attribute block (Tier 2)
```markdown
## disable-account
~~~yaml
timeout: 300000
approval: required           # gate this step behind human approval
in:  [suspects]              # explicit inputs (else inferred from body refs)
out: [disabled]             # named outputs (§8, §5.3)
~~~
```

---

## 5. Queries & collections

A fenced block whose info-string language is a query language is a `query` step.
The body is the query; the info-string carries routing + parameters.

````markdown
## enumerate-spn-requests
```kql target=siem params=(days=lookback)
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID == 4769 and TicketEncryptionType == "0x17"
| summarize requests=count() by Account
```
````

### 5.1 Language tag — open, linted
`query_language` is an **open string**. A compiler MUST NOT reject unknown
languages; a linter SHOULD warn outside a configurable known set (e.g. `kql`,
`spl`, `sql`, `sqlite`, `eql`, `esql`, `esdsl`, `aql`, `osquery`, `cypher`,
`sigma`, `stix`, `yara`, `kestrel`). Runtimes map the tag to whatever transport
they have (see profiles); an unmapped language is a profile-level lint, not a
format error.

### 5.2 Info-string parameters
- `target=<slug>` — a frontmatter `targets:` entry (§6). Required for queries.
- `params=(qname=source, ...)` — bind a query placeholder to a **parameter** or
  a **variable** (`$var`, §5.3). In the body reference it as `{{qname}}` (the
  portable placeholder) or the language's native form. Keeping values out of the
  query text is injection-safe, cacheable, and gives the decompiler structure.
- Any other `key=value` passes through to the step (Tier 2).

### 5.3 Variables & dataflow (`out` / `in`)
A step MAY name outputs and consume prior outputs — this is how expressive
hunts pass data:

````markdown
```kql target=siem out=$spn_events
...
```

## triage
```agent target=hunter in=[$spn_events] out=$verdict
...
```
````

`$name` binds a runtime variable; `{{name}}` interpolates a launch-time
parameter. **Runtime support for `$var` dataflow varies** — a runtime that lacks
it (see the Huntbase profile) lints these steps and offers a documented fallback
(e.g. session/entity scoping). The format keeps dataflow first-class so it stays
expressive and CACAO/SOAR-portable.

### 5.4 Collections
` ```collect ` is a `collection` step (a named data-collection primitive rather
than an ad-hoc query): body is `pack: <name>` or a tool-native spec, with the
same `target=`/`params=` info-string.

---

## 6. Targets (data sources, agents, people)

Declared once in frontmatter `targets:` and referenced by slug. A target is
**abstract** — it names a *kind* of source, not a specific connection:

- Data source: `{ category: siem | endpoint | iam | cloud | network | identity | ... , name }`.
- Agent: `{ agent: true, name, model?: <hint> }` — a reasoning agent; the runtime
  binds which one. `model` is an optional non-binding hint.
- Person/role: `{ role: <role>, name }` or `{ individual: <name> }`.

**Platform binding is optional and namespaced** — a hunt may pin a target to a
specific product for a given runtime without losing portability:

```yaml
targets:
  siem: { category: siem, name: MS Sentinel, huntbase: { product: azure_log_analytics } }
```

A runtime uses its own namespace hint if present, else resolves the abstract
`category` to an available connector, else lints "no source for target `siem`".
The set of targets referenced by query steps is the hunt's **data
requirements** — runtimes use it for a "do you have the sources this hunt needs"
check.

---

## 7. Control flow

### 7.1 Inline grouping (`###`)
`###` steps under a `##` group into a named sub-sequence (path-namespaced slugs)
for modular authoring — authoring sugar, not new semantics. One level deep;
deeper nesting graduates to a separate file + `run:` (§7.5).

### 7.2 Decisions — `if:` (deterministic) / `if~:` (agent-judged)
```markdown
## check-volume
if: `$spn_events.count > 100`
then: → cluster
else: → close-benign
```
`if~:` is an agent-judged (fuzzy) condition with a confidence threshold; the
`indeterminate:` branch is **required**:
```markdown
## looks-like-tunneling
if~: "resembles DNS tunneling rather than CDN traffic" (confidence >= 0.8, judge=hunter)
then: → deep-dive
indeterminate: → manual-review
else: → close-benign
```

### 7.3 Switch (multi-way)
```markdown
## route-by-verdict
switch: `$verdict`
- "malicious"  → contain
- "suspicious" → escalate
- default      → close-benign
```

### 7.4 While (bounded loop)
```markdown
## poll-sandbox
while: `$status != "done"` (max_iterations=20)
do: → fetch-status
```

### 7.5 Sub-playbooks
```markdown
## contain
run: ./contain-host.md          # or a playbook id
with: { $host: $suspect_host }
```

### 7.6 Parallel / join
```markdown
## fan-out
parallel:
- → query-siem
- → query-edr
join: → correlate
```
`join:` makes each branch's tail edge into the join step (concurrency-merge).

---

## 8. Agent steps

An ` ```agent ` block delegates a step to a reasoning agent (the generalization
of a `manual` step from a human to *an* agent — never a specific vendor):

````markdown
## triage-clusters
```agent target=hunter in=[$clusters, $spn_events] out=$verdict,$evidence
objective: >
  For each cluster, determine whether the pattern indicates kerberoasting or
  legitimate service behavior.
tools: [siem, edr]              # target slugs the agent may use this step
success_criteria: >
  $verdict ∈ {malicious, suspicious, benign} per cluster with cited evidence.
max_iterations: 8
```
````

`objective`, `tools` (a target-slug allowlist), `success_criteria`,
`max_iterations`, `in`/`out`. The runtime binds `target=hunter` to whatever agent
it runs (see profiles). Output variables let downstream deterministic steps
consume agent results exactly like query results (the hybrid hinge).

---

## 9. Tasks & actions
- ` ```manual target=<role> ` → a `task` step (human instruction text).
- ` ```action target=<slug> ` → an `action` step (a change/response). Actions
  SHOULD be gated (`~~~yaml approval: required~~~` or a preceding decision).
  Bodies for `bash`/`powershell`/`http`/`openc2` etc. are actions, not queries.

---

## 10. Identity & determinism
On first compile a playbook gets a random id, written back to frontmatter. Every
step/target/variable gets a `uuid5(playbook_id, "<kind>:<slug>")`, so recompiling
an unchanged doc is byte-stable, renames relink, and two docs never collide.
Decompiling third-party graphs derives slugs from names (kebab-cased,
de-duped) and pins original ids in Tier‑2 blocks.

**Determinism label (compiler-emitted, author-immutable):** `deterministic` when
the graph has no `agent` steps, `if~:` decisions, or human `task`s;
`hybrid` otherwise.

---

## 11. Frontmatter/construct → IR (quick reference)

| hunt.md | IR object |
|---|---|
| document | `playbook { id, name, description, metadata }` |
| `## slug` | `step { id, kind, slug, config, edges[] }` |
| query block | `step.kind=query`, `config={query_language, query, params}` |
| ` ```agent ` | `step.kind=agent`, `config={objective, tools, in, out, success_criteria, max_iterations}` |
| `if/if~/switch/while` | `step.kind=decision|loop` |
| ` ```manual ` / ` ```action ` | `step.kind=task | action` |
| `→` / `then/else/indeterminate` | `edge { to, branch: on_true|on_false|default }` |
| `parallel/join` | parallel edges + a merge edge |
| `parameters:` | `parameters[] { name, type, default? }` |
| `targets:` | `targets[] { slug, category|agent|role, bindings{} }` |
| `labels: attack.*` | `attack_techniques[]` |
| `$var` / `{{param}}` | runtime variable / launch parameter |

Runtime/interchange mappings (IR → Huntbase playbook, IR → CACAO v2, IR → docs)
live in **`PROFILES.md`**.

---

## 12. Linting (against a target profile)
A hunt is linted for: flow reachability; variable def-before-use; every query has
a `target`; every `if~:` has `indeterminate:`; every `agent` step has `tools` +
bounds; destructive `action`s are gated; and — per the chosen profile —
unsupported kinds/languages/dataflow reported as actionable warnings, not silent
mis-compiles.
