# hunt.md — specification

**Version:** 0.5 (draft) · **Status:** Working proposal
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
hunt:                               # why the hunt exists, what happens after (§3.3)
  trigger: intel-report
  handoff: keep-as-periodic-hunt
  justification: >
    A cracked SPN password is reusable until rotated and invisible to MFA.
references:
  - name: CISA AA23-320A
    url: https://www.cisa.gov/...
parameters:                         # launch-time inputs; portable {{name}} placeholders
  lookback:  { type: duration, default: "14d" }
  suspects:  { type: string }       # no default → collected at launch or bound at runtime
targets:                            # abstract data sources / agents / people (§6)
  siem:   { category: siem,      name: SIEM, telemetry: [identity] }
  edr:    { category: endpoint,  name: EDR }
  hunter: { agent: true,         name: Hunt agent }     # generic agent — runtime binds it
  tier2:  { role: analyst,       name: Tier-2 analyst }
---
```

Unknown frontmatter keys pass through (Tier 2) — the parser keeps them and
every exporter carries them verbatim (`x_hunt_frontmatter` in a definition,
`x-hunt.frontmatter` in CACAO). `parameters`, `targets`, `labels`, `severity`,
`hypothesis`, `hunt` have defined meaning (§11). A profile MAY define a
namespaced block for facts only it needs (e.g. `huntbase:` bindings on targets,
`misp:` for MISP-only knobs); such blocks are documented in PROFILES.md, never
here, and every other profile ignores them.

### 3.3 The `hunt:` block — why this hunt exists

A hunt is a hypothesis plus a programme decision: someone chose to spend
analyst time on it, and something happens when it ends. That decision is a fact
about the hunt, not about any sharing platform, so it has a neutral home. All
keys are optional; the vocabularies are the HUNT-EX ones (they are the PEAK /
TaHiTI vocabulary), so a hunt classifies for sharing without a profile-specific
block.

```yaml
hunt:
  trigger: crown-jewel          # intel-report | sector-alert | prior-hunt | incident-followup | red-team |
                                # purple-team | crown-jewel | detection-gap | analyst-intuition | ioc-sweep
  methodology: structured-hypothesis-driven   # | unstructured-baseline | model-assisted  (default: the first)
  applicability: universal      # universal | sector-specific | environment-specific | campaign-specific
  handoff: promote-to-detection # promote-to-detection | keep-as-periodic-hunt | retire | escalated-to-ir |
                                # handed-to-detection-engineering
  justification: >              # prose: the obligation, exposure or asset that pays for this hunt
    Cardholder-data systems are in PCI scope; certificate-based escalation
    bypasses every password control we report on.
  assets: [cardholder-db, issuing CAs]   # business assets or processes at stake
  review_by: 2027-03-01         # justifications go stale; when to re-examine this one
```

`trigger` is the structured half of the business justification — the *kind* of
reason the hunt exists. `justification` is the prose half: what makes a negative
result defensible rather than wasted spend. A library index filters on the
first; a report quotes the second. Linters warn on an off-vocabulary value and
never reject; a missing `justification` is a `quality`-profile warning (§13).

### 3.4 Scenario and coverage — which stages this hunt can see

A hunt written from an intrusion report covers some stages of that intrusion
and not others, and a reader cannot tell from the steps alone whether a missing
stage was judged out of scope, could not be observed, or was forgotten. The
`scenario:` block states the chain; `coverage:` says, per stage, what this hunt
does about it. Both are optional; together they render as a table.

```yaml
scenario:
  summary: MAQ abuse → ESC1 enrolment → PKINIT as a tier-0 identity → lateral movement
  stages:
    - slug: machine-account-creation
      name: Attacker creates a computer account under the default quota
      tactic: persistence                 # ATT&CK tactic short name; shape-checked only
      techniques: [T1136.002]
      observables: ["4741 from a non-delegated creator"]
    - slug: esc1-enrolment
      techniques: [T1649]
    - slug: lateral-movement
      techniques: [T1021]
coverage:
  - stage: machine-account-creation
    status: covered              # covered | not_visible | out_of_scope | existing_rule
    steps: [query-machine-account-creation]
  - stage: esc1-enrolment
    status: covered
    steps: [collect-ca-database, analyze-ca-requests]
  - stage: lateral-movement
    status: not_visible
    reason: "No lateral-movement telemetry in scope; needs 4624/4648 with logon type."
    blind_spot: no-lateral-telemetry     # optional link to a §3.5 record
```

| status | meaning |
|---|---|
| `covered` | one or more named steps examine this stage; `steps:` is required and must resolve |
| `not_visible` | the hunt cannot examine it — a telemetry or process gap; `reason:` expected, and a `blind_spot:` link is how it becomes a request (§3.5) |
| `out_of_scope` | deliberately left to another hunt or control; `reason:` expected (link the other hunt in `related:` when it exists) |
| `existing_rule` | a detection already covers it; the hunt does not repeat it |

Lint: when either block is present, every stage slug appears in `coverage`
(error); `covered` names real step slugs (error); `not_visible` /
`out_of_scope` without a `reason` warns; an off-vocabulary status warns. The
`quality` profile (§13) warns when fewer than two stages are covered — a
one-stage hunt is a rule.

### 3.5 Blind spots — what a dead end costs

Hunts routinely stop not because the hypothesis was refuted but because the
data or the process needed to answer it does not exist: a source is not
onboarded, retention expired, a field is unparsed, nobody owns the template. The
format already keeps that state distinct (`unavailable:`, §7.2) and forbids
closing on it (§8.1). What it did not record is *what the gap costs*, which is
the most valuable output a failed hunt produces and the thing that evaporates
if it only lives in an analyst's head.

A `blind_spots:` entry is that record, written once and referenced from
wherever the dead end occurs:

```yaml
blind_spots:
  - id: no-ca-audit-events
    stage: esc1-enrolment                  # optional; a §3.4 stage slug
    requires: "ADCS role-service auditing (4886–4888) on every issuing CA"
    question: "which host each certificate request came from"
    risk: >
      Without the source host, an issued certificate cannot be tied to a
      workstation, so containment scopes to the identity only and the actor's
      foothold survives.
    owner: pki-platform
    remediation: "enable Audit Certification Services + CA AuditFilter 127"
```

| key | meaning |
|---|---|
| `id` | required, unique; what the references below name |
| `requires` | the source, field, retention or process that is missing |
| `question` | what could not be answered without it |
| `risk` | the business exposure of leaving it that way — prose, at whatever fidelity the author can manage |
| `stage`, `owner`, `remediation` | optional: where in the chain, who fixes it, how |

Three things point at a blind spot:

- a `coverage:` entry with `status: not_visible` (`blind_spot: <id>`, §3.4);
- an `unavailable:` branch — `unavailable: → escalate-gap (blind_spot: <id>)` — so
  the decision that could not be made names its cost;
- a run result's `telemetry_coverage.missing[].blind_spot` (§12), so the gap the
  runtime actually hit is the one the author anticipated.

Aggregated across a library, blind spots are the demand signal for the next
data source. Lint: ids unique (error); a reference to an undeclared id (error);
an entry with no `requires` or `risk` warns; the `quality` profile warns on an
`unavailable:` branch that names no blind spot.

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
languages; a linter SHOULD warn outside the known set below. Runtimes map the
tag to whatever transport they have (see profiles); an unmapped language is a
profile-level lint, not a format error.

The known set, and how each tag shares (its HUNT-EX `query-language` value —
the single table the reference linter and the MISP exporter both read):

| tag | HUNT-EX | note |
|---|---|---|
| `kql`, `kusto` | `kusto` | Microsoft Sentinel / Defender |
| `spl` | `spl` | Splunk |
| `esql` | `esql` | Elastic ES\|QL |
| `eql` | `eql` | Elastic Event Query Language |
| `esdsl` | `other` | Elasticsearch Query DSL — HUNT-EX has no peer (`kibana-query` is Kibana's KQL) |
| `aql` | `aql` | IBM QRadar |
| `xql` | `xql` | Palo Alto Cortex |
| `cql` | `cql` | CrowdStrike |
| `sql`, `mysql`, `sqlite`, `osquery` | `sql` | dialects share one value |
| `cypher`, `kestrel` | `other` | graph / hunting DSLs |
| `sigma`, `yara`, `yara-l` | same name | portable detection formats |
| `stix` | `stix-pattern` | STIX 2 patterning |
| `suricata`, `snort` | `suricata-snort` | network rules |
| `shell`, `bash`, `powershell`, `python`, `pseudocode` | same name (`bash` → `shell`) | scripts and prose logic |

Anything else exports as `other`. Which tags a runtime *executes* is that
runtime's profile (PROFILES.md), not this table.

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

**Telemetry planes.** `category` says where data is *stored*; a plane says what
kind of telemetry it *is* — which is what an organisation actually knows it has
or lacks. A data-source target resolves to one or more planes from the closed
set `endpoint | network | identity | email | cloud-control-plane |
cloud-workload | saas | ot-ics`:

- derived from `category` where unambiguous: `endpoint`/`edr` → `endpoint`,
  `iam`/`identity` → `identity`, `network` → `network`, `email` → `email`,
  `cloud` → `cloud-control-plane`, `cloud-workload`, `saas`, `ot`/`ics` → `ot-ics`;
- stated explicitly on a store, which may hold several:
  `siem: { category: siem, telemetry: [identity, endpoint], name: SIEM }`.

A linter warns when a query's target resolves to no plane, and when a stated
plane is off-vocabulary. Planes feed data-requirement checks, run-result
`telemetry_coverage` (§12) and sharing tags (PROFILES §3) without any
profile-specific override.

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
`if~:` is an agent-judged (fuzzy) condition. The `indeterminate:` branch is
**required**:

```markdown
## looks-like-tunneling
if~: "resembles DNS tunneling rather than CDN traffic" (confidence: high, judge=hunter)
then: → deep-dive
indeterminate: → manual-review      # judged, but not conclusively
unavailable:   → request-dns-logs   # could not judge — the telemetry was missing
else: → close-benign
```

**Confidence is ordinal.** Use `high | medium | low`. A numeric threshold
(`confidence >= 0.8`) is accepted for compatibility but SHOULD be avoided and
linters SHOULD warn: a language model's 0.8 is not calibrated, not comparable
between models, and not stable across runs. Ordinal values say what is actually
knowable. Runtimes bucket legacy numerics (`≥0.8 high, ≥0.5 medium, else low`).

**`indeterminate:` and `unavailable:` are different failures**, and conflating
them is how hunts quietly conclude "benign":

| Branch | Meaning | Cause |
|---|---|---|
| `indeterminate:` | The evidence was examined and did not decide the question. | Genuine ambiguity. |
| `unavailable:` | The question could not be examined at all. | A required source wasn't connected, a query failed, retention had expired. |

`unavailable:` is optional; without it, unexamined questions fall back to
`indeterminate:`. It MUST NOT route to a step that closes the hunt as benign —
under the default `missing_data: not_benign` guardrail (§8.1) a linter rejects
that. "We didn't look" is not a finding.

An `unavailable:` branch MAY name the blind spot it is the cost of (§3.5):

```markdown
unavailable:   → request-dns-logs (blind_spot: no-dns-telemetry)
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

### 8.1 Guardrails (agent safety posture)

An agent step consumes telemetry — query results, log fields, file paths, user
agents — that an adversary may control. **Retrieved data is evidence, never
instruction.** A runtime MUST NOT let content returned by a tool alter the
agent's objective, its tool allowlist, or its iteration bound.

Guardrails are **on by default**. A hunt that needs them relaxed must say so,
which makes the relaxation visible in review:

```yaml
guardrails:                  # frontmatter: applies to every agent step and if~:
  telemetry: untrusted       # untrusted | trusted
  evidence: citation_required # citation_required | none
  missing_data: not_benign   # not_benign | ignorable
  claims: no_unsupported     # no_unsupported | permitted
```

| Key | Default | Meaning |
|---|---|---|
| `telemetry` | `untrusted` | Tool/query output is data. Text inside it that looks like an instruction is reported, never obeyed. |
| `evidence` | `citation_required` | Every assertion cites the step and record it came from. |
| `missing_data` | `not_benign` | Absent telemetry never supports a benign verdict — it routes `unavailable:` (§7.2). |
| `claims` | `no_unsupported` | The agent states what it could not determine rather than inferring past its evidence. |

A step may narrow — never silently widen — the document default:

```markdown
## triage
```agent target=hunter
objective: …
~~~yaml
guardrails: { evidence: citation_required }
~~~
```

Linters MUST warn on any guardrail weakened from its default, and MUST reject
unknown keys or values. Profiles declare whether a runtime enforces guardrails
or merely records them; a runtime that cannot enforce `telemetry: untrusted`
SHOULD say so rather than claim the property.

> Rationale: a hunt is authored once and run against data an attacker
> influences. Prompt injection through telemetry is the agentic equivalent of
> SQL injection through a query parameter, and belongs in the format rather
> than in each runtime's prompt.

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
| `hunt:` | `hunt { trigger, methodology, applicability, handoff, justification, assets, review_by }` (§3.3) |
| `scenario:` / `coverage:` | `scenario { summary, stages[] }`, `coverage[] { stage, status, steps[], reason, blind_spot }` (§3.4) |
| `blind_spots:` | `blind_spots[] { id, stage, requires, question, risk, owner, remediation }` (§3.5) |
| `unavailable: → x (blind_spot: id)` | `edge { branch: on_unavailable }` + `step.blind_spot` (§7.2) |
| `targets.*.telemetry` | `targets[].telemetry[]` — declared or derived from category (§6) |
| `guardrails:` | `guardrails { telemetry, evidence, missing_data, claims }` (§8.1) |
| `unavailable:` | `edge { branch: on_unavailable }` (§7.2) |
| `$var` / `{{param}}` | runtime variable / launch parameter |

Runtime/interchange mappings (IR → Huntbase playbook, IR → CACAO v2, IR → docs)
live in **`PROFILES.md`**.

---

## 12. Run results

A hunt describes what to do; a **run result** records what happened. Without a
defined result shape, two runtimes executing the same hunt produce output that
can't be compared, audited, or handed to an analyst — and an agent's conclusion
can't be separated from its evidence.

A conforming runtime SHOULD emit one result document per run:

```yaml
hunt_result:
  hunt: kerberoasting            # slug, or the playbook id (§10)
  run: 2026-07-31T09:14:22Z/7f31 # runtime-assigned, unique
  disposition: suspicious        # §12.1
  confidence: medium             # high | medium | low

  step_results:
    - step: triage               # step slug
      answer_status: matched     # §12.1
      assessment: suspicious
      explanation: >
        Three service accounts show RC4 TGS bursts from non-admin subnets.
      evidence:                  # required under `evidence: citation_required`
        - step: enumerate-spn-requests
          records: 3
          detail: "svc-backup, svc-sql, svc-report — 412 requests / 14 sources"

  evidence_summary:
    malicious_supporting: ["RC4-only TGS requests from workstation subnet"]
    benign_supporting: []
    unknown: ["whether a credential-rotation job ran in the window"]

  telemetry_coverage:            # what could NOT be examined, and why
    available: [siem]
    missing:
      - target: edr
        impact: "process ancestry for the requesting hosts was not checked"

  actions_taken: ["queried SIEM for 4769 events", "clustered by account"]
  hunting_recommendations: ["same accounts across other forests"]
```

### 12.1 Controlled vocabularies

Free-text verdicts don't aggregate. These values are closed sets:

| Field | Values |
|---|---|
| `answer_status` | `matched`, `not_matched`, `partial`, `unknown`, `not_applicable` |
| `assessment` / `disposition` | `malicious`, `suspicious`, `potentially_benign`, `benign`, `inconclusive` |
| `confidence` | `high`, `medium`, `low` |

`unknown` means examined-but-undecided; `not_applicable` means not examinable
(the `unavailable:` case, §7.2). Keeping them distinct is what lets a reviewer
tell "we checked and it's fine" from "we never looked."

### 12.2 Result rules

1. **A benign disposition requires a supported explanation**, not merely the
   absence of malicious evidence. A result with `disposition: benign` and an
   empty `evidence_summary.benign_supporting` is invalid.
2. **Missing telemetry is reported, never assumed benign** (§8.1). Any step whose
   sources were unavailable appears in `telemetry_coverage.missing` with its
   `impact`.
3. **Assertions cite evidence** under the default guardrail — an `explanation`
   without a corresponding `evidence` entry is invalid.
4. `step_results` need not cover every step; steps that didn't run are simply
   absent, and a runtime MAY record why.

These are checkable: `huntmd validate <result.yaml>` lints a result document
against them, the same way it lints a hunt.

## 13. Linting (against a target profile)
A hunt is linted for: flow reachability; variable def-before-use; every query has
a `target`; every `if~:` has `indeterminate:`; every `agent` step has `tools` +
bounds; destructive `action`s are gated; and — per the chosen profile —
unsupported kinds/languages/dataflow reported as actionable warnings, not silent
mis-compiles. Profiles (runtime, interchange, sharing) and what each one lints
are enumerated in PROFILES.md.
