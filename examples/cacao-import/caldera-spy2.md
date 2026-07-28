---
type: investigation
name: Super Spy (Caldera Only)
labels:
- hunt
- TODO-attack-technique
hypothesis: 'Playbook Implementing Cacao Profile: Super Spy'
parameters:
  host_file_path:
    type: string
  host_dir_staged:
    type: string
  host_dir_compress:
    type: string
targets:
  source:
    category: unknown
    name: 'TODO: name the data source'
x_cacao_source:
  id: Playbook UUID-003
x_source:
  repo: https://github.com/davidojeabulu/caldera-cacao-importer
  path: test_playbooks/SuperSpyCaldera.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Super Spy (Caldera Only)

Playbook Implementing Cacao Profile: Super Spy

## screen-capture
```action
{'id': '316251ed-6a28-4013-812b-ddf5b5b007f8'}
```
~~~yaml
cacao_id: step-uuid002
command_type: attack-cmd
~~~

## copy-clipboard
```action
{'id': 'b007fe0c-c6b0-4fda-915c-255bbc070de2'}
```
~~~yaml
cacao_id: step-uuid003
command_type: attack-cmd
~~~

## get-chrome-bookmarks
```action
{'id': 'b007fc38-9eb7-4320-92b3-9a3ad3e6ec25'}
```
~~~yaml
cacao_id: step-uuid004
command_type: attack-cmd
~~~

## record-microphone
```action
{'id': '78524da1-f347-4fbb-9295-209f1f408330'}
```
~~~yaml
cacao_id: step-uuid005
command_type: attack-cmd
~~~

## create-staging-directory
```action
{'id': '6469befa-748a-4b9c-a96d-f191fde47d89'}
```
~~~yaml
cacao_id: step-uuid006
command_type: attack-cmd
~~~

## find-files
```action
{'id': '90c2efaa-8205-480d-8bb6-61d90dbaf81b'}
```
~~~yaml
cacao_id: step-uuid007
command_type: attack-cmd
~~~

## stage-sensitive-files
```action
{'id': '4e97e699-93d7-4040-b5a3-2e906a58199e'}
```
~~~yaml
cacao_id: step-uuid008
command_type: attack-cmd
~~~

## compress-staged-directory
```action
{'id': '300157e5-f4ad-4569-b533-9d1fa0e74d74'}
```
~~~yaml
cacao_id: step-uuid009
command_type: attack-cmd
~~~

## exfil-staged-directory
```action
{'id': 'ea713bc4-63f0-491c-9a6f-0b01d560b87e'}
```
~~~yaml
cacao_id: step-uuid010
command_type: attack-cmd
~~~

## find-files-2
```action
{'id': '90c2efaa-8205-480d-8bb6-61d90dbaf81b'}
```
~~~yaml
cacao_id: step-uuid011
command_type: attack-cmd
~~~

## discover-antivirus-programs
```action
{'id': '2dece965-37a0-4f70-a391-0f30e3331aba'}
```
~~~yaml
cacao_id: step-uuid012
command_type: attack-cmd
~~~
→ end
