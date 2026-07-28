---
type: notification
name: Example ssh
labels:
- hunt
- soarca
- openc2
- post
- TODO-attack-technique
severity: low
hypothesis: This playbook is to demonstrate the openc2 functionality
references:
- name: TNO COSSAS
  url: https://cossas-project.org
targets:
  soarca-openc2-http:
    agent: true
    name: soarca-openc2-http
  httpbin:
    category: http-api
    name: httpbin
x_cacao_source:
  id: playbook--300270f9-0e64-42c8-93cc-0927edbe3ae7
  spec_version: cacao-2.0
  created: '2023-11-20T15:56:00.123456Z'
  created_by: identity--96abab60-238a-44ff-8962-5806aa60cbce
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/openc2-playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Example ssh

This playbook is to demonstrate the openc2 functionality

## openc2
```action target=soarca-openc2-http
POST post HTTP1.1
```
~~~yaml
cacao_id: action--eb9372d4-d524-49fc-bf24-be26ea084779
command_type: openc2
~~~
→ end
