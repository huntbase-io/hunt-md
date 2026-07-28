---
type: investigation
name: Incident Responder 1
labels:
- hunt
- TODO-attack-technique
hypothesis: 'Playbook Implementing Cacao Profile: Incident Responder'
targets:
  source:
    category: unknown
    name: 'TODO: name the data source'
x_cacao_source:
  id: Playbook UUID-001
x_source:
  repo: https://github.com/davidojeabulu/caldera-cacao-importer
  path: test_playbooks/IncidentResponder.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Incident Responder 1

Playbook Implementing Cacao Profile: Incident Responder

## find-unauthorised-processes
```action
ps aux | grep -v grep | grep #{remote.port.unauthorized} | awk '{print $2}'
```
~~~yaml
cacao_id: step-uuid002
command_type: ssh
~~~

## find-atypical-open-ports
```action
Compare open ports against a known baseline
```
~~~yaml
cacao_id: step-uuid003
command_type: ssh
~~~

## acquire-suspcious-files
```action
Get information from AV about suspicious files
```
~~~yaml
cacao_id: step-uuid004
command_type: ssh
~~~

## suspicious-urls-in-mail
```action
Finds suspicious URLs in received mail
```
~~~yaml
cacao_id: step-uuid005
command_type: ssh
~~~

## hunt-for-known-suspicious-files
```action
Use hash of known suspicious file to find instances of said file on hosts
```
~~~yaml
cacao_id: step-uuid006
command_type: ssh
~~~

## kill-rogue-processes
```action
Force kill any unauthorized processes
```
~~~yaml
cacao_id: step-uuid007
command_type: ssh
~~~

## enable-inbound-tcp-udp-firewall-rule
```action
Blocks inbound TCP and UDP traffic on a specific port
```
~~~yaml
cacao_id: step-uuid008
command_type: ssh
~~~

## enable-outbound-tcp-udp-firewall-rule
```action
Blocks outbound TCP and UDP traffic on a specific port
```
~~~yaml
cacao_id: step-uuid009
command_type: ssh
~~~

## delete-known-suspicious-files
```action
Use hash of known suspicious file to find instances of said file, and delete instances
```
~~~yaml
cacao_id: step-uuid010
command_type: ssh
~~~

## inoculate-c2
```action
Reroute suspicious IP addresses to localhost by editing hosts file
```
~~~yaml
cacao_id: step-uuid011
command_type: ssh
~~~

## search-for-powershell-executionpolicy-bypass-elastic
```action
Search for Sysmon Event 1 powershell records with 'ExecutionPolicy' and 'Bypass'
```
~~~yaml
cacao_id: step-uuid012
command_type: ssh
~~~
→ end
