---
type: investigation
name: Super Spy
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
  id: Playbook UUID-002
x_source:
  repo: https://github.com/davidojeabulu/caldera-cacao-importer
  path: test_playbooks/SuperSpy.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Super Spy

Playbook Implementing Cacao Profile: Super Spy

## screen-capture
```action
capture the contents of the screen
```
~~~yaml
cacao_id: step-uuid002
command_type: ssh
~~~

## copy-clipboard
```action
pbpaste
```
~~~yaml
cacao_id: step-uuid003
command_type: ssh
~~~

## get-chrome-bookmarks
```action
Get Chrome Bookmarks
```
~~~yaml
cacao_id: step-uuid004
command_type: ssh
~~~

## record-microphone
```action
brew install sox >/dev/null 2>&1; sox -d recording.wav trim 0 15 >/dev/null 2>&1;
```
~~~yaml
cacao_id: step-uuid005
command_type: ssh
~~~

## create-staging-directory
```action
mkdir -p staged && echo $PWD/staged
```
~~~yaml
cacao_id: step-uuid006
command_type: ssh
~~~

## find-files
```action
Locate files deemed sensitive
```
~~~yaml
cacao_id: step-uuid007
command_type: ssh
~~~

## stage-sensitive-files
```action
cp #{host.file.path[filters(technique=T1005,max=3)]} #{host.dir.staged[filters(max=1)]}
```
~~~yaml
cacao_id: step-uuid008
command_type: ssh
~~~

## compress-staged-directory
```action
Compress a directory on the file system
```
~~~yaml
cacao_id: step-uuid009
command_type: ssh
~~~

## exfil-staged-directory
```action
Exfil the staged directory
```
~~~yaml
cacao_id: step-uuid010
command_type: ssh
~~~

## find-files-2
```action
Locate files deemed sensitive
```
~~~yaml
cacao_id: step-uuid011
command_type: ssh
~~~

## discover-antivirus-programs
```action
Identify AV
```
~~~yaml
cacao_id: step-uuid012
command_type: ssh
~~~
→ end
