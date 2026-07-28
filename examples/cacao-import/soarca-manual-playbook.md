---
type: notification
name: Example manual
labels:
- hunt
- soarca
- manual
- TODO-attack-technique
severity: low
hypothesis: This playbook is to demonstrate the manual command definition
references:
- name: COSSAS
targets:
  soarca-manual-capability:
    agent: true
    name: soarca-manual-capability
  soarca-manual:
    agent: true
    name: soarca-manual
  luke-skywalker:
    individual: Luke Skywalker
    name: Luke Skywalker
x_cacao_source:
  id: playbook--fe65ef7b-e8b1-4ed9-ba60-3c380ae5ab28
  spec_version: cacao-2.0
  created: '2025-01-21T14:14:23.263Z'
  created_by: identity--ac3c0258-7a81-46e7-a2ae-d34b6d06cc54
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/manual-playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Example manual

This playbook is to demonstrate the manual command definition

## manual
```manual target=soarca-manual
prepare Falcon for hyperspeed jump
```
~~~yaml
cacao_id: action--eb9372d4-d524-49fc-bf24-be26ea084779
~~~
→ end
