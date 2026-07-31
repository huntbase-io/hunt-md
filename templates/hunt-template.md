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
references:
  - name: <source>
    url: <url>

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
  # add: { type: string | number | boolean | duration | host | ip | date | query | ... }

# --- Abstract data sources / agents / people --------------------------------
targets:
  siem:   { category: siem,      name: SIEM }          # + optional per-runtime binding:
  # edr:  { category: endpoint,  name: EDR, huntbase: { product: msatp } }
  hunter: { agent: true,         name: Hunt agent }    # an agent; the runtime binds which one
  tier2:  { role: analyst,       name: Tier-2 analyst }
---

# <Hunt name>

<Short description of what this hunt does and how it flows.>

## <first-query-step>
```<language> target=siem params=(days=lookback)
<your query — reference parameters as {{days}}>
```

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
context: [<first-query-step>]           # prior step slugs whose results to read
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
