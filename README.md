<div align="center">

# hunt.md

**An open, portable Markdown format for threat-hunting playbooks.**

[![Spec](https://img.shields.io/badge/spec-v0.6%20draft-blue)](./SPEC.md)
[![Profiles](https://img.shields.io/badge/profiles-Huntbase%20%7C%20CACAO%20v2%20%7C%20MISP%20%7C%20docs-6f42c1)](./PROFILES.md)
[![Python](https://img.shields.io/badge/tooling-python%20%E2%89%A5%203.10-3776ab)](./tools)
[![License](https://img.shields.io/badge/license-see%20LICENSE-lightgrey)](./LICENSE)

[Spec](./SPEC.md) · [Profiles](./PROFILES.md) · [Contributing](./CONTRIBUTING.md) · [Hunt library](./hunts) · [Tooling](./tools)

</div>

---

A `hunt.md` file describes a hunt as a readable, git-diffable document *and* a
typed graph of steps — queries, data collection, agent reasoning, decisions,
human review, and response — that a compliant runtime can render, review, and
run.

> **Write once; read it anywhere; run it wherever you have the connectors.**

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

## triage
```agent target=hunter
objective: Are these accounts being kerberoasted, or is this legitimate service traffic?
tools: [siem]
```
→ end
````

That's the whole file. YAML frontmatter for metadata, one `##` heading per step,
fenced blocks for the work. No schema to learn before you can read it.

---

## Why hunt.md

|   | |
|---|---|
| **Portable & vendor-neutral** | The format defines its own model. Query languages, agents, and data sources are open — nothing ties a hunt to one product. A hunt runs on any runtime that has the connectors. |
| **Human-first** | Plain Markdown + YAML. Review it in a PR, render it anywhere, edit it without tooling. |
| **Deterministic *and* agentic** | "Run this exact query" and "an agent should investigate X" are both first-class — because real hunts are hybrid. |
| **Agent-neutral** | A step can delegate to *an* agent; the runtime binds which one. No agent, vendor, or model is baked into the format. |
| **Useful at every level** | Level 0: a readable doc + AI-assistant context, zero tooling. Level 1+: import into a runtime and it *executes*. |
| **Safe by default** | Retrieved telemetry is evidence, never instruction. Guardrails are on unless a hunt explicitly relaxes them, and missing data never reads as "benign". |

## How it runs — profiles

The format is neutral; **profiles** adapt it to a target and declare what that
target supports.

| Profile | What it does |
|---|---|
| **[Huntbase](https://www.huntbase.io)** | Imports a hunt.md as a launchable hunt playbook and executes it — queries against connectors, agent steps, gated actions. |
| **CACAO v2** | Exports to OASIS CACAO JSON for STIX/TAXII sharing and SOAR. |
| **Generic / docs-only** | Renders as a document and feeds AI assistants. No execution. |

The [capability matrix](./PROFILES.md#capability-matrix-at-a-glance) shows exactly
what each runtime supports. The same file works everywhere, gaining capability as
it moves to a more capable runtime — a gap is a *runtime* limit, never a *format* one.

## Quickstart

```bash
git clone <this repo> && cd hunt-md
cp templates/hunt-template.md hunts/my-hunt.md
```

1. **Copy the template** into `hunts/`, named for the hunt (`hunts/<short-slug>.md`).
2. **Fill in** the hypothesis, targets, parameters, and steps — see [`SPEC.md`](./SPEC.md).
3. **Lint it** with `huntmd validate hunts/my-hunt.md` (see [Tooling](#tooling)) — reachability,
   variable use, agent bounds, and gated destructive actions (see [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
4. **Open a PR.** Describe the threat, the data sources needed, and known false positives.
5. **Run it** — import into a runtime (e.g. [Huntbase](https://www.huntbase.io)) to launch,
   or export to CACAO to share.

## Tooling

[`tools/huntmd`](./tools) is the reference converter + validator — stdlib + PyYAML only,
so it vendors cleanly into a runtime's import path.

```bash
cd tools && pip install -e .

huntmd validate ../hunts/kerberoasting.md              # lint against a profile
huntmd convert  ../hunts/kerberoasting.md              # → Huntbase definition YAML
huntmd convert  ../hunts/kerberoasting.md --to cacao   # → CACAO v2 playbook JSON
huntmd convert  ../hunts/kerberoasting.md --to misp    # → MISP event (HUNT-EX tags + threat-hunt-* objects)
huntmd convert  ../my-hunt.definition.yaml             # → hunt.md (inverse)
huntmd convert  ../some-cacao-playbook.json            # CACAO → hunt.md (draft)
huntmd convert  ../some-misp-event.json                # MISP → hunt.md (exact if exported by huntmd, else draft)
huntmd validate ../examples/results/kerberoasting-run.yaml  # lint a run result
```

CACAO import/export is round-trip exact and tested against
[49 real playbooks](./examples/cacao-import) from six independent projects.
MISP export uses the [HUNT-EX](https://github.com/MISP/misp-taxonomies/tree/main/hunt-ex)
taxonomy and `threat-hunt-*` objects so peers can filter for hunts they can
reproduce; the source travels as an attachment, so import is exact
(see [`examples/misp-export/`](./examples/misp-export)).

See [`tools/README.md`](./tools/README.md) for the full CLI.

## Repository layout

| Path | |
|---|---|
| [`SPEC.md`](./SPEC.md) | The format specification (vendor-neutral) |
| [`PROFILES.md`](./PROFILES.md) | Runtime/interchange adapters + capability matrix |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | How to add a hunt + the lint rules |
| [`templates/`](./templates) | `hunt-template.md` — start here |
| [`hunts/`](./hunts) | The hunt library (one `.md` per hunt) |
| [`tools/`](./tools) | `huntmd` — reference converter + validator (Python) |
| [`examples/`](./examples) | Reference conversions from other formats (not curated hunts) |

## Status

**Draft format — SPEC v0.6.** Evolving in the open. See [`SPEC.md`](./SPEC.md) §1
for design principles, [`CHANGELOG.md`](./CHANGELOG.md) for what changed and
what stayed compatible, and [`CONTRIBUTING.md`](./CONTRIBUTING.md) to help.

## License

See [`LICENSE`](./LICENSE).
