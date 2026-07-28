---
type: investigation
name: Phishing Email Investigation & Response
labels:
- hunt
- phishing
- email-security
- automated
- attack.t1204.001
- attack.t1566.001
- attack.t1566.002
severity: high
hypothesis: Automated investigation and response workflow for reported phishing emails.
  Extracts IOCs, checks reputation, and takes containment actions.
references:
- name: MITRE ATT&CK - T1566.001
  url: https://attack.mitre.org/techniques/T1566/001/
- name: MITRE ATT&CK - T1566.002
  url: https://attack.mitre.org/techniques/T1566/002/
- name: MITRE ATT&CK - T1204.001
  url: https://attack.mitre.org/techniques/T1204/001/
parameters:
  email_id:
    type: string
    description: The ID of the reported phishing email
  sender_address:
    type: string
    description: Extracted sender email address
  malicious_urls:
    type: string
    description: List of malicious URLs found in the email
  verdict:
    type: string
    description: 'Final verdict: malicious, suspicious, or clean'
  severity_score:
    type: string
    description: Calculated severity score (0-100)
targets:
  source:
    category: unknown
    name: 'TODO: name the data source'
x_cacao_source:
  id: playbook--88fe2d32-2514-46e5-8f25-83af42240a59
  spec_version: cacao-2.0
  created: '2026-02-09T19:26:21.641Z'
  created_by: identity--676becc0-7756-4056-a890-4fb144bc5ab2
x_source:
  repo: https://github.com/ugurrates/playbookforge
  path: playbookforge/backend/tests/fixtures/sample_phishing_playbook.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Phishing Email Investigation & Response

Automated investigation and response workflow for reported phishing emails. Extracts IOCs, checks reputation, and takes containment actions.

## extract-email-metadata
```action
GET /api/v1/email/parse?id={{email_id}}
```
~~~yaml
cacao_id: action--d90d67dc-7c6d-4572-91c4-ead8082762ef
command_type: http-api
~~~

## extract-iocs
```action
POST /api/v1/ioc/extract
```
~~~yaml
cacao_id: action--d9505917-ded1-4aee-8efe-592d1e91a67f
command_type: http-api
~~~

## check-url-reputation
```action
POST /api/v1/reputation/url
```
~~~yaml
cacao_id: action--3741a69e-b82e-4a63-bc2c-c530c2f6aa22
command_type: http-api
~~~

## check-sender-reputation
```action
POST /api/v1/reputation/sender
```
~~~yaml
cacao_id: action--f9fde2cd-77e7-4336-8bbd-0ffd17e19606
command_type: http-api
~~~

## is-email-malicious
if: `$$verdict$$ == 'malicious'`
then: → block-sender-domain
else: → update-case-status
~~~yaml
cacao_id: if-condition--9e883947-9d28-480c-b0b7-8a8a9d3831a6
~~~

## block-sender-domain
```action
POST /api/v1/blocklist/domain
```
~~~yaml
cacao_id: action--f8a6bf2c-61a5-4ded-b158-b985d48895b2
command_type: http-api
~~~

## search-for-other-recipients
```action
POST /api/v1/email/search
```
~~~yaml
cacao_id: action--c69bda88-fff7-4bd3-8752-bf38b1382ecb
command_type: http-api
~~~

## delete-phishing-emails
```action
POST /api/v1/email/purge
```
~~~yaml
cacao_id: action--740efb17-b264-4eae-b026-9305cdffc73f
command_type: http-api
~~~

## notify-soc-team-lead
```manual
Send email notification to SOC Team Lead with phishing incident summary
```
~~~yaml
cacao_id: action--a7b560cb-d1ed-48f5-915b-9ca34b213225
~~~
→ update-case-status

## update-case-status
```action
PATCH /api/v1/case/update
```
~~~yaml
cacao_id: action--2abab70c-bad8-4a9f-8f80-c45b0200b153
command_type: http-api
~~~
→ end
