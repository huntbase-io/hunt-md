---
type: notification
name: SOARCA Main Flow
labels:
- hunt
- soarca
- TODO-attack-technique
severity: low
hypothesis: This playbook will run for each trigger event in SOARCA
references:
- name: TNO SOARCA
  url: http://tno.nl/cst
parameters:
  var1:
    type: string
  var2_not_external:
    type: string
targets:
  firewall-1:
    agent: true
    name: Firewall 1
  banana-rama:
    agent: true
    name: banana rama
x_cacao_source:
  id: playbook--61a6c41e-6efc-4516-a242-dfbc5c89d562
  spec_version: cacao-2.0
  created: '2023-05-26T15:56:00.123456Z'
  created_by: identity--5abe695c-7bd5-4c31-8824-2528696cdbf1
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# SOARCA Main Flow

This playbook will run for each trigger event in SOARCA

## imc-assets-by-cve
```action target=banana-rama
GET http://__imc_address__/by/__cve__
```
~~~yaml
cacao_id: action--a76dbc32-b739-427b-ae13-4ec703d5797e
command_type: http-api
~~~

## bia-for-cve
```action target=banana-rama
GET http://__bia_address__/analysisreport/__cve__
```
~~~yaml
cacao_id: action--9fcc5c3b-0b70-4d73-b922-cf5491dcd1a4
command_type: http-api
~~~

## generate-coas
```action target=banana-rama
GET http://__coagenerator_address__/coa/__assetuuid__
```
~~~yaml
cacao_id: action--09b97fab-56a1-45dc-a88f-be3cde3eac33
command_type: http-api
~~~

## bia-for-coas
```action target=banana-rama
GET http://__bia_address__/analysisreport/__coa_list__
```
~~~yaml
cacao_id: action--2190f685-1857-44ac-ad0e-0ded6c6ef3ce
command_type: http-api
~~~
→ end
