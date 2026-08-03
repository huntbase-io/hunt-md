# Announcing hunt.md — an open, portable format for threat-hunting playbooks

**TL;DR** — `hunt.md` is a Markdown format for writing threat hunts as readable,
git-diffable documents that are also executable graphs. It's vendor-neutral,
agent-neutral, MIT-licensed, and useful with zero tooling. v0.4 of the spec is
out, along with a reference converter that round-trips to OASIS CACAO v2 —
tested against 49 real playbooks from six independent projects.

→ **[github.com/huntbase-io/hunt-md](https://github.com/huntbase-io/hunt-md)**

---

## The problem

Threat hunts live in two bad places.

The first is people's heads — a hypothesis, a couple of saved queries, and the
context of why the hunt exists at all, none of it written down anywhere a
colleague can find. The hunt runs once, finds nothing, and is gone.

The second is a vendor's UI. The hunt gets built properly this time: queries,
branching, a triage step, a containment action. But it's now a row in someone's
database, expressible only through that product's editor, reviewable only by
clicking through it, and unusable the moment you change stacks or want to share
it with a peer at another company.

Detections solved this years ago. Sigma made a detection a file — something you
write in an editor, review in a pull request, diff, fork, and share. Hunts never
got that. They're more complex than detections, not less: a hunt is a *sequence*
of steps with branching, human judgement, and — increasingly — an agent doing
some of the reasoning. That complexity is exactly why hunts need a source format,
not a UI.

## What hunt.md is

A hunt is one Markdown file. YAML frontmatter for metadata, one `##` heading per
step, fenced blocks for the work:

````markdown
---
type: investigation
labels: [hunt, attack.t1558.003]
severity: high
hypothesis: Service accounts are being kerberoasted from non-admin workstations.
parameters:
  lookback: { type: duration, default: "14d" }
targets:
  siem:   { category: siem, name: SIEM }
  hunter: { agent: true,    name: Hunt agent }
---

# Kerberoasting hunt

## enumerate-spn-requests
```kql target=siem params=(days=lookback)
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID == 4769 and TicketEncryptionType == "0x17"
| summarize requests=count() by Account
```

## check-volume
if: `enumerate-spn-requests.rows > 0`
then: → triage
else: → end

## triage
```agent target=hunter
objective: Are these accounts being kerberoasted, or is this legitimate service traffic?
tools: [siem]
max_iterations: 6
```
→ end
````

That file is simultaneously three things: a document a human reads, a diff a
reviewer approves in a PR, and a typed graph a runtime can execute.

## Four decisions worth explaining

**Deterministic and agentic are both first-class.** Real hunts are hybrid. Some
steps are "run exactly this query against this source." Others are "figure out
whether this pattern is malicious." Most formats can express the first and treat
the second as a comment. hunt.md gives them equal standing — an `agent` step has
an objective, a tool allowlist, success criteria, and an iteration bound, and its
outputs feed downstream deterministic steps like any query result.

**Agent-neutral, not agent-free.** A step delegates to *an* agent. It never names
a vendor, product, or model. The runtime binds which agent actually runs. An
`if~:` condition — an agent-judged predicate with a confidence threshold — must
route its `indeterminate:` branch somewhere, usually to a human. The format takes
the position that fuzzy judgement is legitimate but must be bounded and
auditable.

**Capability profiles, not lowest-common-denominator.** The format stays
expressive: runtime dataflow, loops, sub-playbooks, parallel branches. Each
runtime publishes what it supports, and the linter tells you what a given hunt
needs versus what your target provides. A construct your runtime can't execute
still renders, still diffs, still exports. Gaps are runtime limits, stated
explicitly — never silent mis-compiles.

**Useful at level zero.** A hunt.md file with no tooling at all is still a
well-structured document and high-quality context for an AI assistant. Add the
converter and it lints. Import it into a runtime and it runs. Nothing about the
on-ramp requires buying anything.

## Interoperability: CACAO, both directions

[OASIS CACAO](https://www.oasis-open.org/committees/cacao/) v2 is the standard
for moving playbooks between organizations and SOAR platforms, and it's a good
one — well-specified, STIX/TAXII-native, signable. hunt.md doesn't compete with
it. It's the authoring layer above it.

The division of labour is the point: CACAO JSON is excellent for machines and
miserable to hand-write or code-review — hundreds of lines of nested objects with
UUID cross-references, where a one-character change is an unreadable diff. You
write the hunt in Markdown, review it in a PR, and compile to CACAO when it's
time to ship.

```bash
huntmd convert hunts/kerberoasting.md --to cacao   # → CACAO v2 playbook JSON
huntmd convert some-playbook.json                  # CACAO → hunt.md
```

Both directions work. Export produces a complete CACAO 2.0 playbook with
deterministic identifiers, so an unchanged hunt re-exports byte-identically.
Import accepts CACAO 1.x and 2.0, every workflow step type, and the command
types that actually appear in the wild.

We didn't want to claim that on the strength of our own test fixtures, so we ran
it against real data: **49 CACAO playbooks from six independent projects**. All
49 import, parse, and lint clean, with all 332 workflow steps preserved. Running
real playbooks surfaced four bugs that our own examples never would have — which
is rather the point of doing it.

A round-trip of a hunt.md through CACAO and back is exact: step kinds, slugs,
targets, parameters, and every edge survive.

## What's shipping today

- **[SPEC.md](https://github.com/huntbase-io/hunt-md/blob/main/SPEC.md)** — the
  format, v0.4 draft. Steps, control flow, targets, agents, the fidelity model,
  identity and determinism rules.
- **[PROFILES.md](https://github.com/huntbase-io/hunt-md/blob/main/PROFILES.md)** —
  runtime and interchange adapters, with a capability matrix stating exactly what
  each supports.
- **`huntmd`** — reference converter and linter. Python 3.10+, stdlib and PyYAML
  only, so it vendors cleanly into a runtime's import path.
- **Two reference hunts** — Kerberoasting, and a Scattered Spider identity-takeover
  hunt exercising parallel branches, fuzzy conditions, and gated response.
- **Reference conversions** from real CACAO playbooks, plus a script that
  reproduces the full corpus locally.

## Honest status

It's a **draft** at v0.4, evolving in the open, and we'd rather say what isn't
finished than have you discover it:

- The hunt library is **two hunts**. That's a seed, not a library. It grows
  through contributions.
- There's **no CI** wired up yet — the linter exists and runs locally.
- CACAO export is structurally complete but **not schema-validated** against the
  OASIS spec by our tooling. Run it through a CACAO validator before publishing.
- The Huntbase profile doesn't execute `while:` loops or inline sub-playbooks
  today. The linter tells you so rather than pretending otherwise.

## Contributing

The most useful thing you can give this project is **a hunt**. Copy
[`templates/hunt-template.md`](https://github.com/huntbase-io/hunt-md/blob/main/templates/hunt-template.md),
fill in the hypothesis and steps, open a PR. The lint rules are in
[CONTRIBUTING.md](https://github.com/huntbase-io/hunt-md/blob/main/CONTRIBUTING.md)
and they're mostly about rigour: every fuzzy condition routes its indeterminate
case, every agent step is bounded, every destructive action is gated.

The second most useful thing is **disagreement with the spec**. It's v0.4 for a
reason. If a construct doesn't fit how you actually hunt, that's a bug in the
format.

MIT licensed. Built by [Huntbase](https://www.huntbase.io), designed to outlive
any one vendor — including us.

→ **[github.com/huntbase-io/hunt-md](https://github.com/huntbase-io/hunt-md)**
