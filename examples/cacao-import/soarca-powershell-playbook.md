---
type: investigation
name: SOARCA PowerShell playbook
labels:
- hunt
- TODO-attack-technique
hypothesis: This playbook demonstrates the powershell capability
targets:
  soarca-powershell:
    agent: true
    name: soarca-powershell
  windows:
    category: net-address
    name: Windows
x_cacao_source:
  id: playbook--6673b5cb-d9e9-408e-ab50-2fbb9abe91f5
  spec_version: cacao-2.0
  created: '2024-08-27T09:28:36.611Z'
  created_by: identity--691f1eb6-2a1e-495b-8f5e-18f44380c26a
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/powershell-playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# SOARCA PowerShell playbook

This playbook demonstrates the powershell capability

## powershell-example
```action target=soarca-powershell
pwd
```
~~~yaml
cacao_id: action--010b0420-db3e-4810-ba75-08a10f473214
command_type: powershell
~~~
→ end
