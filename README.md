# hunt.md

**An open, portable Markdown format for threat-hunting playbooks.**

A `hunt.md` file describes a hunt as a readable, git-diffable document *and* a
typed graph of steps — queries, data collection, agent reasoning, decisions,
human review, and response — that a compliant runtime can render, review, and
run. Write once; read it anywhere; run it wherever you have the connectors.

```markdown
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

## triage
```agent target=hunter
objective: Are these accounts being kerberoasted, or is this legitimate service traffic?
tools: [siem]
```
→ end
```

## Why hunt.md

- **Portable & vendor-neutral.** The format defines its own model. Query
  languages, agents, and data sources are open — nothing ties a hunt to one
  product. A hunt runs on any runtime that has the connectors.
- **Human-first.** Plain Markdown + YAML. Review it in a PR, render it anywhere,
  edit it without tooling.
- **Deterministic *and* agentic.** "Run this exact query" and "an agent should
  investigate X" are both first-class — because real hunts are hybrid.
- **Agent-neutral.** A step can delegate to *an* agent; the runtime binds which
  one. No agent/vendor/model is baked into the format.
- **Useful at every level.** Level 0: a readable doc + AI-assistant context, zero
  tooling. Level 1+: import into a runtime and it *executes*.

## How it runs — profiles

The format is neutral; **profiles** adapt it to a target and declare what that
target supports (see [`PROFILES.md`](./PROFILES.md)):

- **Huntbase** — imports a hunt.md as a launchable hunt playbook and executes it
  (queries against connectors, agent steps, gated actions).
- **CACAO v2** — exports to OASIS CACAO JSON for STIX/TAXII sharing and SOAR.
- **Generic / docs-only** — renders + feeds AI assistants; no execution.

A capability matrix ([`PROFILES.md`](./PROFILES.md#capability-matrix-at-a-glance))
shows exactly what each runtime supports; the same file works everywhere, gaining
capability as it moves to a more capable runtime.

## Repository layout

```
SPEC.md            the format specification (vendor-neutral)
PROFILES.md        runtime/interchange adapters + capability matrix
CONTRIBUTING.md    how to add a hunt + the lint rules
templates/         hunt-template.md — start here
hunts/             the hunt library (one .md per hunt)
tools/             huntmd — reference converter + validator (Python)
```

## Tooling

`tools/huntmd` is the reference converter + validator (stdlib + PyYAML):

```bash
cd tools
python -m huntmd validate ../hunts/kerberoasting.md          # lint
python -m huntmd convert  ../hunts/kerberoasting.md          # → Huntbase definition YAML
```

See [`tools/README.md`](./tools/README.md).

## Quickstart

1. Copy `templates/hunt-template.md` into `hunts/` and name it for the hunt.
2. Fill in the hypothesis, targets, parameters, and steps (see [`SPEC.md`](./SPEC.md)).
3. Open a PR. CI lints reachability, variable use, agent bounds, and that
   destructive actions are gated (see [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
4. Import it into a runtime (e.g. Huntbase) to launch it, or export to CACAO to
   share it.

## Status
Draft format (SPEC v0.4). Evolving in the open. See [`SPEC.md`](./SPEC.md) §1 for
design principles and [`CONTRIBUTING.md`](./CONTRIBUTING.md) to help.

## License
See [`LICENSE`](./LICENSE).
