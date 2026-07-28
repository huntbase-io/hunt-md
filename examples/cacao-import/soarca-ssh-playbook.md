---
type: notification
name: Example ssh
labels:
- hunt
- soarca
- ssh
- example
- TODO-attack-technique
severity: low
hypothesis: This playbook demonstrates ssh functionality
references:
- name: TNO COSSAS
  url: https://cossas-project.org
targets:
  soarca-ssh:
    agent: true
    name: soarca-ssh
  system-1:
    category: ssh
    name: system 1
x_cacao_source:
  id: playbook--300270f9-0e64-42c8-93cc-0927edbe3ae7
  spec_version: cacao-2.0
  created: '2023-11-20T15:56:00.123456Z'
  created_by: identity--96abab60-238a-44ff-8962-5806aa60cbce
x_source:
  repo: https://github.com/COSSAS/SOARCA
  path: test/playbook/ssh-playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Example ssh

This playbook demonstrates ssh functionality

## execute-command
```action target=soarca-ssh
__command__:value
```
~~~yaml
cacao_id: action--eb9372d4-d524-49fc-bf24-be26ea084779
command_type: ssh
~~~

## touch-file
```action target=soarca-ssh
touch __path__:value
```
~~~yaml
cacao_id: action--88f4c4df-fa96-44e6-b310-1c06d193ea55
command_type: ssh
~~~
→ end
