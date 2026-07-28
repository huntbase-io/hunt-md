---
type: investigation
name: Phishing Email Investigation & Response
labels:
- hunt
- phishing
- email-security
- automated
- TODO-attack-technique
severity: high
hypothesis: Automated investigation and response workflow for reported phishing emails.
  Extracts IOCs, checks reputation, and takes containment actions.
targets:
  source:
    category: unknown
    name: 'TODO: name the data source'
x_cacao_source:
  id: playbook--a]1b2c3d4-e5f6-7890-abcd-ef1234567890
  spec_version: cacao-2.0
  created: '2025-06-15T10:30:00.000Z'
  created_by: identity--f1a773d0-81c4-4a9e-8e41-bb5c3a2f0e01
x_source:
  repo: https://github.com/ugurrates/playbookforge
  path: playbooks/phishing-investigation.json
  license: Apache-2.0
  note: Converted from CACAO by `huntmd convert`; a draft, not a curated hunt.
---

# Phishing Email Investigation & Response

Automated investigation and response workflow for reported phishing emails. Extracts IOCs, checks reputation, and takes containment actions.

## extract-email-metadata
```manual
Extract email headers, sender address, subject line, and body content from the reported phishing email.
```
~~~yaml
cacao_id: step--extract-metadata
~~~

## extract-iocs
```manual
Extract URLs, IP addresses, domain names, and file hashes from the email content and attachments.
```
~~~yaml
cacao_id: step--extract-iocs
~~~

## check-url-reputation
```manual
Submit extracted URLs to VirusTotal and URLhaus for reputation scoring.
```
~~~yaml
cacao_id: step--check-url-reputation
~~~

## check-sender-reputation
```manual
Check sender address against internal blocklist and external threat feeds.
```
~~~yaml
cacao_id: step--check-sender
~~~

## is-email-malicious
if: `verdict == 'malicious'`
then: → block-sender-domain
else: → update-case-benign
~~~yaml
cacao_id: step--is-malicious
~~~

## block-sender-domain
```manual
Add sender domain to Exchange Online / email gateway blocklist.
```
~~~yaml
cacao_id: step--block-sender
~~~

## search-for-other-recipients
```manual
Query email logs for messages from the same sender with matching subject line.
```
~~~yaml
cacao_id: step--search-recipients
~~~

## delete-phishing-emails
```manual
Execute compliance search and purge action to remove phishing emails from all mailboxes.
```
~~~yaml
cacao_id: step--delete-emails
~~~
→ end

## update-case-benign
```manual
Update case status to 'Benign' and send notification to the original reporter.
```
~~~yaml
cacao_id: step--update-case-benign
~~~
→ end
