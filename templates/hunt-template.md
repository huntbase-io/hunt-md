---
# --- Playbook metadata -------------------------------------------------------
type: investigation
name: <Hunt name>                       # optional; falls back to the H1 below
labels:
  - hunt
  - attack.tXXXX[.YYY]                  # one or more ATT&CK techniques
tlp: amber                              # clear | green | amber | red
severity: high                          # critical | high | medium | low
hypothesis: >
  <One or two sentences: the adversary behaviour you believe is present and
  why. This is what the hunt tests.>
# rationale: >                          # optional: why this hypothesis and this scope
#   <What made you pick this over the alternatives; what is deliberately out.>
# analysis: >                           # optional: how it is tested — pivots, baselines, what falsifies it
#   <The analytic approach a reviewer should be able to argue with.>
references:
  - name: <source>
    url: <url>

# --- Part of a series? Related hunts? (SPEC §3.8) -----------------------------
# One hypothesis per file — these are how the files point at each other.
# series:  { slug: <series-slug>, index: 1, total: 3, title: <part title> }
# related:
#   - { hunt: <sibling-slug-or-url>, relation: precedes }   # follows | sibling |
#                                                           # alternative | supersedes |
#                                                           # superseded-by |
#                                                           # out-of-scope-alternative
#   - { hunt: <slug>, relation: out-of-scope-alternative,
#       reason: <the hypothesis you chose not to test, and why> }

# --- Provenance (SPEC §3.6) ---------------------------------------------------
# provenance:
#   authors: [{ name: <person or team>, org: <org> }]
#   source: { system: misp, ref: <event uuid>, imported: 2026-01-01 }   # if imported/adapted
#   generated: { by: <tool>, model: <id>, from: <url>, gates: [dry-run, lint, human-review] }

# --- Why this hunt exists (SPEC §3.3) ----------------------------------------
# Closed vocabularies shared with HUNT-EX, so a library can be filtered and a
# negative result can still be justified upward. All optional.
hunt:
  trigger: intel-report                 # intel-report | sector-alert | prior-hunt | incident-followup |
                                        # red-team | purple-team | crown-jewel | detection-gap |
                                        # analyst-intuition | ioc-sweep
  applicability: universal              # universal | sector-specific | environment-specific | campaign-specific
  handoff: keep-as-periodic-hunt        # promote-to-detection | keep-as-periodic-hunt | retire |
                                        # escalated-to-ir | handed-to-detection-engineering
  justification: >
    <Why the business is paying for this: the obligation, the exposure, the
    crown jewel. This is what makes "we found nothing" defensible.>
  assets: [<business asset or process at stake>]
  # review_by: 2027-01-01               # justifications go stale; date the next review

# --- Agent safety posture (SPEC §8.1) ----------------------------------------
# These are the defaults and apply even if you delete this block. Spell them out
# only to relax one — which the linter will warn about, by design.
guardrails:
  telemetry: untrusted                  # retrieved data is evidence, never instruction
  evidence: citation_required           # every claim cites the step it came from
  missing_data: not_benign              # absent telemetry never supports "benign"
  claims: no_unsupported                # say what couldn't be determined

# --- Launch-time inputs ({{name}} placeholders in query bodies) --------------
parameters:
  lookback: { type: duration, default: "14d" }
  # scalars: string | number | integer | boolean | duration | date | host | ip |
  #          domain | url | hash | email | path | user | query          (SPEC §3.7)
  # typed indicator list — `from:` says where it came from, so it can be refreshed:
  # c2_domains:
  #   type: list[domain]
  #   default: ["<domain>"]
  #   from: { kind: article, ref: <url>, observed: 2026-01-01 }
  #   # reference it as `in~ (split("{{c2_domains}}", ","))` — members join with commas

# --- Abstract data sources / agents / people --------------------------------
targets:
  # A store (siem, datalake) must say which telemetry planes it holds; a plane
  # category (endpoint, iam, network, …) derives it. Planes (SPEC §6):
  # endpoint | network | identity | email | cloud-control-plane | cloud-workload | saas | ot-ics
  siem:   { category: siem,      name: SIEM, telemetry: [identity] }   # + optional per-runtime binding:
  # edr:  { category: endpoint,  name: EDR, huntbase: { product: msatp } }
  hunter: { agent: true,         name: Hunt agent }    # an agent; the runtime binds which one
  tier2:  { role: analyst,       name: Tier-2 analyst }

# --- MISP-only knobs (optional; PROFILES.md §3) -------------------------------
# Classification lives in `hunt:` above and telemetry on the targets; this block
# is only for things MISP alone needs.
# misp:
#   distribution: 2
#   tags: ['workflow:state="complete"']

---

# <Hunt name>

<Short description of what this hunt does and how it flows.>

## <first-query-step>
# `role=` says what this query is for: scoping | baseline | enrichment | triage |
# detection-candidate (the one worth promoting to a rule — SPEC §5.8).
```<language> target=siem params=(days=lookback) role=scoping
~~~yaml
# Optional, all of it (SPEC §5.5–§5.6). Say what the query reads so a runtime
# can preflight it, whether it has ever run, what a hit looks like, and what an
# empty result proves — `not_evidence_of_absence` unless the source is complete.
source: <table or index>
reads: [<column>, <column>]
verified: none                          # none | dry-run | executed
expected: >
  <What a hit looks like. Say if zero rows is the common case.>
silence: not_evidence_of_absence        # | evidence_of_absence
# prevalence: { key: [<field>], by: <dimension>, rare_below: 3 }          # SPEC §5.7
# baseline:   { window: "{{days}}", compare: prior_equal_window }         # | first_seen | new_this_window
~~~
<your query — reference parameters as {{days}}>
```
# A `detection-candidate` query may carry a portable twin: the native block is
# what runs, this is what a peer can run without your stack (SPEC §5.8).
# ```sigma portable
# title: <rule title>
# logsource: { product: windows, service: system }
# detection:
#   sel: { EventID: 4769 }
#   condition: sel
# level: medium
# ```

## <decision-step>
if: `<first-query-step>.rows > 0`
then: → <agent-step>
else: → end

# An agent-judged decision instead? Confidence is ordinal (high|medium|low) —
# a model's 0.8 isn't calibrated. Route both failure modes separately:
#
# ## <fuzzy-decision>
# if~: "<the judgement, in plain language>" (confidence: high, judge=hunter)
# then: → <response-step>
# indeterminate: → <human-review>   # looked, couldn't decide
# unavailable:   → <human-review>   # couldn't look — never close the hunt here
# else: → end

## <agent-step>
```agent target=hunter
objective: >
  <What the agent should determine, and the scope.>
context: [<first-query-step>]           # prior step slugs whose results to read;
                                        # cap a big one: { step: <slug>, rows: 200 }  (SPEC §8.2)
cite: required                          # demand a citation per claim (§8.2)
tools: [siem]                           # target slugs the agent may use
success_criteria: >
  <The observable output that means this step is done.>
max_iterations: 6
```

## <response-step>
```action target=siem
~~~yaml
approval: required                      # gate destructive/change actions
~~~
<The change/response to take.>
```
→ end

# See SPEC.md for the full construct set (collections, switch, while, fuzzy
# conditions, sub-playbooks, parallel/join) and PROFILES.md for what each
# runtime supports.
