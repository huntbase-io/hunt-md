# Launch collateral — hunt.md

Copy-paste ready. Every claim here is checkable against the repo; nothing is
rounded up. Repo: `https://github.com/huntbase-io/hunt-md`

---

## X / Twitter — thread

**1/**
Threat hunts live in two bad places: someone's head, or a vendor's UI.

Detections got Sigma — a file you write, review, diff, and share. Hunts never got
that.

So we built it. hunt.md: an open Markdown format for threat-hunting playbooks.

github.com/huntbase-io/hunt-md

**2/**
A hunt is one Markdown file.

YAML frontmatter for metadata. One `##` heading per step. Fenced blocks for the
work.

It's a document a human reads, a diff a reviewer approves, and a typed graph a
runtime executes — at the same time.

[ATTACH: hero image — the kerberoasting hunt]

**3/**
The bit most formats get wrong: real hunts are hybrid.

Some steps are "run exactly this query."
Others are "figure out if this is actually malicious."

hunt.md makes both first-class. An agent step has an objective, a tool
allowlist, success criteria, and an iteration bound.

**4/**
And it's agent-neutral.

A step delegates to *an* agent — never a named vendor, product, or model. The
runtime binds which one actually runs.

No agent is baked into the format. That's deliberate. Formats outlive models.

**5/**
Fuzzy judgement is allowed, but it has to be bounded.

`if~:` is an agent-judged condition with a confidence threshold — and it MUST
route its `indeterminate:` branch somewhere. Usually to a human.

The linter enforces it. "The AI wasn't sure" is a state you handle, not ignore.

**6/**
Portability isn't a promise, it's a matrix.

Every runtime publishes what it supports. The linter tells you what your hunt
needs vs. what your target provides.

A construct your runtime can't execute still renders, still diffs, still exports.
Gaps are stated, never silently mis-compiled.

**7/**
On CACAO: we like it. OASIS CACAO v2 is the right standard for moving playbooks
between orgs and SOAR platforms.

hunt.md isn't a competitor — it's the authoring layer above it.

You write Markdown and review it in a PR. You ship CACAO.

**8/**
Both directions work, and we didn't want to claim that on our own test fixtures.

So we ran it against 49 real CACAO playbooks from 6 independent projects.

All 49 import, parse and lint clean. 332/332 workflow steps preserved.

Found 4 bugs our own examples never would have.

**9/**
Status, honestly: it's a v0.4 draft.

The hunt library is *two hunts*. That's a seed, not a library.
No CI yet.
Export isn't schema-validated against the OASIS spec.

We'd rather tell you than have you find out.

**10/**
Most useful thing you can contribute: a hunt.

Second most useful: disagreement with the spec. If a construct doesn't fit how
you actually hunt, that's a bug in the format.

MIT. Built by @huntbase, designed to outlive any one vendor — including us.

github.com/huntbase-io/hunt-md

---

## LinkedIn

**Threat hunts live in two bad places: someone's head, or a vendor's UI.**

In the first case the hunt runs once, finds nothing, and disappears — along with
the hypothesis and the reason it existed. In the second it gets built properly,
then becomes a row in a database, reviewable only by clicking through a UI and
unusable the moment you change stacks.

Detections solved this years ago. Sigma made a detection a *file* — something you
write in an editor, review in a pull request, diff, fork, and share. Hunts never
got the same treatment, despite being more complex, not less: a hunt is a
sequence of steps with branching, human judgement, and increasingly an agent
doing some of the reasoning.

Today we're releasing **hunt.md** — an open, vendor-neutral Markdown format for
threat-hunting playbooks.

A hunt is one Markdown file: YAML frontmatter for metadata, one heading per step,
fenced blocks for queries and agent directives. It's simultaneously a document a
human reads, a diff a reviewer approves, and a typed graph a runtime can execute.

Three decisions shaped it:

→ **Deterministic and agentic are both first-class.** "Run this exact query" and
"an agent should investigate this" are native constructs, because real hunts are
hybrid. Agent steps are bounded — objective, tool allowlist, success criteria,
iteration limit — and their outputs feed downstream steps like any query result.

→ **Agent-neutral by design.** A step delegates to *an* agent, never a named
vendor or model. The runtime binds which one. Formats outlive models.

→ **Interoperability with OASIS CACAO, in both directions.** CACAO v2 is the
right standard for sharing playbooks between organizations, and hunt.md is the
authoring layer above it — you write and review Markdown, you ship CACAO. We
validated that against 49 real CACAO playbooks from six independent projects:
all import, parse and lint cleanly, with all 332 workflow steps preserved.

It's a v0.4 draft and we're being direct about what isn't done: the hunt library
is two reference hunts, there's no CI yet, and CACAO export isn't schema-verified
against the OASIS spec. Those are stated in the repo rather than buried.

MIT licensed. The most useful contribution is a hunt; the second most useful is
telling us where the spec doesn't match how you actually work.

github.com/huntbase-io/hunt-md

#ThreatHunting #DFIR #DetectionEngineering #SecurityAutomation #OpenSource #CACAO

---

## Bluesky / Mastodon

Threat hunts live in two bad places: someone's head, or a vendor's UI.

Detections got Sigma. Hunts never got the equivalent.

hunt.md — an open Markdown format for threat-hunting playbooks. Readable
document, reviewable diff, executable graph. Deterministic *and* agentic steps.
Round-trips to OASIS CACAO v2.

MIT, v0.4 draft.

github.com/huntbase-io/hunt-md

---

## Hacker News

**Title:** `hunt.md – An open Markdown format for threat-hunting playbooks`

**First comment (from the submitter):**

Author here. Context on why this exists:

Detection rules got a portable source format years ago (Sigma). Threat hunts
didn't, even though they're structurally harder — a hunt is a sequence of steps
with branching, human decision points, and increasingly an LLM agent doing some
of the triage. That work currently lives either in someone's head or inside a
vendor's UI, where you can't diff it, review it in a PR, or hand it to a peer at
another company.

hunt.md is one Markdown file per hunt: YAML frontmatter, one `##` heading per
step, fenced code blocks carrying the queries. The same file is a readable
document and a typed graph a runtime can execute.

Two design points that might interest this crowd:

1. Agent steps are first-class but agent-*neutral*. A step delegates to "an
   agent" with an objective, a tool allowlist, and an iteration bound — it never
   names a vendor or model, and the runtime binds which one runs. Fuzzy
   conditions (`if~:`) carry a confidence threshold and are required by the
   linter to route an `indeterminate:` branch, usually to a human.

2. Rather than a lowest-common-denominator format, each runtime publishes a
   capability profile and the linter reports what a hunt needs versus what your
   target supports. Unsupported constructs are reported, never silently
   mis-compiled.

There's a converter that round-trips to OASIS CACAO v2 in both directions. I
tested it against 49 real CACAO playbooks pulled from six unrelated GitHub
projects rather than just our own fixtures — all 49 import and lint clean with
all 332 workflow steps preserved, and doing that surfaced four bugs synthetic
examples wouldn't have.

It's a v0.4 draft. The hunt library is two hunts, there's no CI yet, and export
isn't schema-validated against the OASIS spec — all noted in the repo. MIT
licensed. Happy to answer questions, and genuinely interested in where the model
breaks for how other people hunt.

---

## Reddit — r/threathunting, r/blueteamsec, r/cybersecurity

**Title:** `We open-sourced a Markdown format for threat-hunting playbooks (hunt.md)`

Sigma made detections portable — a file you can write, review, diff, and share.
Hunts never got that, so they end up either undocumented or locked in a vendor's
UI.

hunt.md is one Markdown file per hunt. Frontmatter carries the hypothesis, ATT&CK
labels, parameters, and data sources. Each `##` heading is a step: a query, a
data collection, an agent directive, a decision, a human task, or a gated
response action. Document order is the default flow; `→ target` jumps override it.

Things that might matter to you specifically:

- **Queries stay parameterized.** `params=(days=lookback)` + `{{days}}` rather
  than string-concatenated values — injection-safe, and importers can collect
  inputs at launch.
- **Agent steps are bounded and auditable.** Tool allowlist, success criteria,
  max iterations. Fuzzy conditions must route an "indeterminate" branch, normally
  to a human analyst. The linter fails you otherwise.
- **Destructive actions must be gated** behind approval or a preceding decision.
- **Exports to OASIS CACAO v2** for sharing over STIX/TAXII, and imports back.
  Validated against 49 real CACAO playbooks from six projects.

Zero tooling required to get value — it renders as a readable doc and works well
as context for an AI assistant. The converter/linter is Python, stdlib + PyYAML.

It's a v0.4 draft and the library is only two hunts so far, which is the main
thing we'd like help with. MIT licensed.

github.com/huntbase-io/hunt-md

---

## Blurb bank

**One-liner (≤100 chars)**
> An open, portable Markdown format for threat-hunting playbooks.

**Elevator (≤280 chars)**
> hunt.md makes a threat hunt a file: readable document, reviewable diff,
> executable graph. Deterministic *and* agentic steps, agent-neutral by design,
> round-trips to OASIS CACAO v2. MIT licensed.

**GitHub repo description**
> An open, portable Markdown format for threat-hunting playbooks — readable
> document, reviewable diff, executable graph.

**Conference/CFP abstract seed**
> Detection engineering got a portable source format; threat hunting didn't.
> This talk covers what breaks when you try to version-control a hunt — branching
> flow, human decision points, and LLM agents doing part of the triage — and a
> format design that handles all three while staying vendor- and agent-neutral,
> including lessons from round-tripping 49 real OASIS CACAO playbooks.

---

## Visual collateral (suggested)

1. **Hero image** — the kerberoasting hunt.md, syntax-highlighted, full file in
   one screen. The whole pitch is "it fits on a screen and you can read it."
2. **Side-by-side** — the same playbook as hunt.md vs. as CACAO JSON. Nothing
   argues for an authoring layer better than the line counts.
3. **Flow diagram** — the step graph of the Scattered Spider hunt (parallel
   queries → correlate → agent triage → fuzzy decision → gated containment),
   showing the doc and the graph are the same object.

**Alt text for #1:** "A hunt.md file for a Kerberoasting hunt: YAML frontmatter
declaring the hypothesis, ATT&CK technique T1558.003, a lookback parameter and
SIEM and agent targets, followed by a KQL query step, a decision step, and an
agent triage step."

---

## Timing / sequencing notes

- Publish the announcement post first so every social link has a destination.
- HN and Reddit reward the honest-limitations framing; keep the "two hunts, no CI"
  paragraph in. Removing it is the fastest way to get picked apart in comments.
- The 49-playbook validation is the single most credible detail here — it's
  evidence rather than assertion. Lead with it wherever there's room.
- Have the contribution path ready before posting: the ask is hunts, and people
  act on it within the first hour or not at all.
