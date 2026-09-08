---
type: investigation
name: ADCS ESC1 certificate-template abuse hunt
labels:
  - hunt
  - attack.t1649        # steal or forge authentication certificates
  - attack.t1136.002    # create account: domain account (machine-account quota abuse)
  - attack.t1078.002    # valid accounts: domain accounts
  - attack.t1550.003    # use alternate authentication material: pass the ticket (PKINIT)
tlp: green            # derived from public sources; no org-specific detail
severity: critical
hypothesis: >
  A low-privileged principal has enrolled — or attempted to enroll — a
  certificate from a misconfigured ADCS template that permits an enrollee-supplied
  subject (ESC1), naming a higher-privileged identity, and has used the resulting
  certificate to authenticate as that identity via PKINIT.
rationale: >
  ESC1 is the most common ADCS misconfiguration and the one CISA's red team
  used at both AA26-237A organisations. The CA database is chosen as the
  primary source over the event log because it records denied requests, needs
  no logging enabled, and survives a CA rebuild that would erase the audit
  trail. Other ESC variants are deliberately out of scope: they need
  template-specific reasoning and belong in sibling hunts.
analysis: >
  Collect the ESE database from every issuing CA and the template ACLs from
  the directory in parallel with the corroborating event queries; isolate
  requests whose SAN or CommonName names a principal other than the
  requester; let an agent correlate those against template flags,
  machine-account creation and PKINIT logons. What falsifies the hypothesis is
  a complete collection with zero such requests; what refutes a candidate is
  an enrollment-agent or web-server template used as designed.
hunt:                   # why this hunt exists and what happens after (SPEC §3.3)
  trigger: intel-report
  applicability: universal
  handoff: promote-to-detection
  justification: >
    A certificate issued through an ESC1 template is a credential that survives
    password resets, is valid for a year by default, and authenticates as any
    identity the enrollee chose — including domain administrators. CISA's red
    team used exactly this chain to take two critical-infrastructure domains.
    Nothing that watches passwords sees it, so this hunt is the only control
    until every issuing CA's templates are hardened and audited.
  assets: [Active Directory, issuing CAs, tier-0 identities]
  review_by: 2027-03-01
related:                # hypotheses this hunt deliberately does not test (SPEC §3.8)
  - hunt: adcs-esc8-ntlm-relay-to-web-enrollment
    relation: out-of-scope-alternative
    reason: >
      ESC8 (NTLM relay to the CA web-enrollment endpoint) reaches the same
      outcome through a different mechanism and needs network telemetry this
      hunt does not collect. It is a sibling hunt, not a branch of this one.
  - hunt: adcs-template-misconfiguration-audit
    relation: alternative
    reason: >
      A configuration audit answers "could this happen?" from the templates
      alone; this hunt answers "did it happen?" from the request history. Run
      the audit if you have no CA database to collect.
scenario:               # the chain this hunt was written from, and what it can see of it (SPEC §3.4)
  summary: >
    Default machine-account quota → computer account → ESC1 enrolment naming a
    tier-0 UPN → PKINIT as that identity → lateral movement and cloud identity
    (AA26-237A, both organisations).
  stages:
    - slug: machine-account-creation
      name: Attacker creates a computer account under ms-DS-MachineAccountQuota
      tactic: persistence
      techniques: [T1136.002]
      observables: ["4741 whose creator is not a delegated joiner", "4742 editing dNSHostName or SPN straight after"]
    - slug: esc1-enrolment
      name: Enrollee-supplied SAN naming another principal, issued or denied
      tactic: privilege-escalation
      techniques: [T1649]
      observables: ["CA database request where RequesterName ≠ SAN/CommonName", "4886/4887/4888 with a SAN attribute"]
    - slug: certificate-logon
      name: PKINIT TGT for the impersonated identity
      tactic: defense-evasion
      techniques: [T1550.003, T1078.002]
      observables: ["4768 with Certificate Information for a tier-0 account", "KDC 39/41"]
    - slug: lateral-movement
      name: Use of the obtained identity on other hosts
      tactic: lateral-movement
      techniques: [T1021]
    - slug: cloud-pivot
      name: Hybrid identity used to reach the cloud tenant
      tactic: lateral-movement
      techniques: [T1550.001]
coverage:
  - stage: machine-account-creation
    status: covered
    steps: [query-machine-account-creation]
  - stage: esc1-enrolment
    status: covered
    steps: [collect-ca-database, enumerate-template-acls, query-ca-audit-events, analyze-ca-requests]
  - stage: certificate-logon
    status: covered
    steps: [query-certificate-logons, query-kdc-cert-mapping]
  - stage: lateral-movement
    status: out_of_scope
    reason: >
      Once an identity is confirmed impersonated, host-to-host movement is the
      incident's problem, not the hunt's; contain hands it to the incident
      commander.
  - stage: cloud-pivot
    status: not_visible
    reason: >
      No cloud sign-in telemetry is in scope for this hunt; a hybrid-joined
      impersonated identity reaching the tenant would not be seen here.
    blind_spot: no-cloud-signin
blind_spots:            # what each dead end costs, so it becomes a request rather than a shrug (SPEC §3.5)
  - id: no-ca-audit-events
    stage: esc1-enrolment
    requires: "ADCS role-service auditing (4886–4888) enabled on every issuing CA"
    question: "which host each certificate request was submitted from"
    risk: >
      The CA database records who requested a certificate but not from where.
      Without the source host, containment scopes to the identity only and the
      workstation the actor is on keeps its foothold.
    owner: pki-platform
    remediation: "Audit Certification Services subcategory + CA AuditFilter 127"
  - id: uncollected-ca
    stage: esc1-enrolment
    requires: "raw-disk collection from every issuing CA in the forest, not just the ones known to the SOC"
    question: "whether an ESC1 request was made at all"
    risk: >
      An issuing CA that was never collected is an issuing CA whose entire
      request history is unknown; a single such host makes every negative
      result from this hunt unreportable.
    owner: pki-platform
  - id: no-template-owner
    requires: "a named owner per published certificate template"
    question: "whether an enrollment naming another principal was intended"
    risk: >
      Without an owner to confirm intent, a suspicious request cannot be
      closed either way, and the template stays enrollable while the question
      waits.
    owner: pki-platform
  - id: no-cloud-signin
    stage: cloud-pivot
    requires: "cloud identity sign-in telemetry joined to on-premises identities"
    question: "whether an impersonated hybrid identity reached the tenant"
    risk: >
      AA26-237A ended in cloud compromise at both organisations; this hunt
      would confirm the on-premises escalation and miss the part that mattered.
references:
  - name: "GuidePoint Security — Hunting Abuse: Detecting Privilege Escalation Through the ADCS Database"
    url: https://www.guidepointsecurity.com/blog/detecting-privilege-escalaction-through-adcs/
  - name: CISA AA26-237A — A Tale of Two SOCs (MAQ → ESC1 → certificate impersonation)
    url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a
  - name: MITRE ATT&CK T1649 — Steal or Forge Authentication Certificates
    url: https://attack.mitre.org/techniques/T1649/
  - name: SpecterOps — Certified Pre-Owned (ESC1–ESC8)
    url: https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
  - name: Microsoft KB5014754 — certificate-based authentication changes on Windows domain controllers
    url: https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

parameters:
  lookback:     { type: duration, default: "30d" }
  # The CA database is queried in SQL, not with a relative window: bind this to
  # the same instant as `lookback` at launch (ISO-8601, UTC).
  window_start: { type: date }
  # Issuing CA hosts to sweep. Enumerate from the pKIEnrollmentService objects in
  # the Configuration NC — every issuing CA, not just the ones you remember.
  ca_hosts:     { type: string }
  # Principals whose impersonation is a tier-0 event. Tune per environment.
  tier0_pattern: { type: string, default: "^(administrator|krbtgt|.*adm.*|.*[-_]da|.*[-_]ea)$" }

provenance:
  authors: [{ name: Huntbase, org: huntbase.io }]
  generated:
    by: claude-code
    model: claude-fable-5-1
    from: https://www.guidepointsecurity.com/blog/detecting-privilege-escalaction-through-adcs/
    gates: [lint, human-review]   # queries have not been executed against a live estate (see verified: none)
targets:
  ca:     { category: endpoint, name: Issuing CA host(s) }
  cadb:   { category: endpoint, name: "ADCS CA database (ESE, collected)" }
  ad:     { category: identity, name: Directory (LDAP / AD audit) }
  siem:   { category: siem,     name: SIEM, telemetry: [identity] }
  hunter: { agent: true,        name: Hunt agent }
  tier2:  { role: analyst,      name: Tier-2 analyst }
  pki:    { role: pki-owner,    name: AD/PKI platform owner }

---

# ADCS ESC1 certificate-template abuse hunt

Hunts certificate-based privilege escalation from the CA database outward. The CA
database records every request — including the denied and failed ones — with no
additional logging enabled, so it is the authoritative source and the event log is
corroboration, not the other way round. Collection and the corroborating event
queries fan out in parallel; a SQL pass over the collected database isolates
requests where the enrollee named someone other than themselves; an agent
correlates those against template configuration, machine-account creation and
PKINIT logons. Absent telemetry routes to a gap escalation, never to a benign
close.

## fan-out
parallel:
- → collect-ca-database
- → enumerate-template-acls
- → query-machine-account-creation
- → query-ca-audit-events
- → query-certificate-logons
- → query-kdc-cert-mapping
join: → analyze-ca-requests

## collect-ca-database
```collect target=ca params=(hosts=ca_hosts)
~~~yaml
timeout: 1800000
notes: >
  Read the ESE database through a raw NTFS accessor so the CA service is never
  stopped and the file lock is irrelevant, then replay the transaction logs
  (edb*.log) so uncommitted recent requests are not lost. Requires a collector
  whose ESE reader decodes DateTime columns as FILETIME rather than OLE doubles —
  an implementation that gets this wrong silently resolves every timestamp to
  1899-12-30T00:00:00Z, which looks like a parsing quirk and is actually a
  destroyed timeline (fixed in Velociraptor 0.76.6+).
~~~
pack: adcs.ca-database
# Default path: C:\Windows\System32\CertLog\<CA common name>.edb
# Tables that matter:
#   Requests            — submitter identity, submission/resolution timestamps,
#                         disposition (including denials), requested CommonName
#   Certificates        — issued certificate metadata: serial, thumbprint,
#                         NotBefore/NotAfter, revocation time
#   RequestAttributes   — client-supplied attributes: CertificateTemplate and the
#                         SAN, which is where the ESC1 enrollee writes the UPN of
#                         the identity being impersonated
#   Requests inline text — the same attribute text embedded in the Requests row;
#                         use it as a fallback when RequestAttributes is sparse
```

## enumerate-template-acls
```collect target=ad
pack: adcs.certificate-templates
# ESC1 needs ALL of these true on one template that is published on an Enterprise
# CA (listed in certificateTemplates on a pKIEnrollmentService object — an
# unpublished template is not enrollable). Return every attribute below so
# triage-candidates can evaluate the combination rather than guess:
#   msPKI-Certificate-Name-Flag & 0x00000001   CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
#   msPKI-Enrollment-Flag       & 0x00000002 == 0   no PEND_ALL_REQUESTS, i.e.
#                                              no certificate-manager approval
#   msPKI-RA-Signature == 0                    no enrollment-agent signature
#   pKIExtendedKeyUsage contains any of
#       1.3.6.1.5.5.7.3.2        Client Authentication
#       1.3.6.1.4.1.311.20.2.2   Smart Card Logon
#       1.3.6.1.5.2.3.4          PKINIT Client Authentication
#       2.5.29.37.0              Any Purpose
#     (an empty pKIExtendedKeyUsage — a subordinate-CA template — is worse: ESC2)
#   nTSecurityDescriptor grants the Enroll extended right
#       0e10c968-78fb-11d2-90d4-00c04f79dc55  (Enroll)
#       a05b8cc2-17bc-4802-a710-e7c15ab866a2  (AutoEnroll)
#     to a broad principal: Domain Users, Authenticated Users, Domain Computers,
#     Everyone, or any group whose membership is effectively open.
# Also return ms-DS-MachineAccountQuota from the domain NC — a non-zero quota is
# what turns "any authenticated user" into "any authenticated user with a fresh
# computer account to enroll with" (AA26-237A).
```

## query-machine-account-creation
```kql target=siem params=(days=lookback)
~~~yaml
prevalence: { key: [Creator], by: NewComputer, rare_below: 2 }   # one non-delegated creator, one new computer, is enough
baseline: { window: "{{days}}", compare: new_this_window }
~~~
// AA26-237A chain step 1: default ms-DS-MachineAccountQuota (10) lets any
// authenticated user create a computer account, which then becomes the ESC1
// enrollee. A computer account created by a non-delegated, non-admin user — and
// especially one whose dNSHostName or SPN is edited straight afterwards — is the
// tell. Empty result with a non-zero quota means "not used", not "not possible".
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID in (4741,   // a computer account was created
                    4742)   // a computer account was changed
| extend Creator     = strcat(SubjectDomainName, "\\", SubjectUserName),
         NewComputer = TargetUserName
| summarize events = make_list(pack("t", TimeGenerated, "id", EventID), 50),
            first_seen = min(TimeGenerated)
    by NewComputer, Creator
| project first_seen, NewComputer, Creator, events
```

## query-ca-audit-events
```kql target=siem params=(days=lookback)
~~~yaml
source: SecurityEvent
reads: [TimeGenerated, Computer, EventID, SubjectUserName, WorkstationName, EventData]
verified: none
expected: >
  4886/4887 rows whose Attributes carry a SAN naming a principal other than the
  requester; 4888 rows are attempts. Zero rows is the common case even on an
  abused CA, because this auditing is off by default.
silence: not_evidence_of_absence
~~~
// Corroboration only. ADCS role-service auditing is OFF by default (it needs the
// CA's AuditFilter plus "Audit Certification Services"), and it is the first
// thing lost in a CA rebuild — so an empty result here is a telemetry gap, not
// evidence of absence. What it adds over the CA database is the requester's
// source host, which the database does not store.
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID in (4886,   // Certificate Services received a request
                    4887,   // request approved, certificate issued
                    4888,   // request denied
                    4889,   // request set to pending
                    4890,   // certificate manager settings changed
                    4898,   // certificate template loaded
                    4899,   // certificate template updated
                    4900)   // certificate template security updated
| extend Requester  = coalesce(column_ifexists("Requester", ""), SubjectUserName),
         RequestID  = column_ifexists("RequestId", ""),
         Attributes = column_ifexists("Attributes", "")  // carries the client SAN
| project TimeGenerated, Computer, EventID, Requester, RequestID, Attributes, WorkstationName
```

## query-certificate-logons
```kql target=siem params=(days=lookback, tier0=tier0_pattern)
// The escalation landing: 4768 populates the Certificate Information fields only
// for PKINIT. A TGT for a tier-0 principal issued against a certificate whose
// serial or thumbprint matches a request found in analyze-ca-requests closes the
// loop from "a certificate was issued" to "it was used to become that identity".
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID == 4768
| where isnotempty(column_ifexists("CertThumbprint", ""))
     or isnotempty(column_ifexists("CertSerialNumber", ""))
| extend Account = tolower(TargetUserName)
| where Account matches regex "{{tier0}}"
| project TimeGenerated, Computer, Account, IpAddress,
          CertIssuerName, CertSerialNumber, CertThumbprint, TicketEncryptionType
```

## query-kdc-cert-mapping
```kql target=siem params=(days=lookback) role=detection-candidate
// KB5014754 KDC events. In Compatibility mode the KDC logs rather than blocks a
// weak mapping, which makes these the highest-signal, lowest-volume artefact of
// certificate impersonation available: 39 = certificate valid but not strongly
// mapped, 41 = mismatch between the certificate SID extension and the account.
// If the domain is already at Full Enforcement, expect KDC-side denials instead.
Event
| where TimeGenerated > ago({{days}})
| where Source == "Microsoft-Windows-Kerberos-Key-Distribution-Center"
| where EventID in (39, 40, 41)
| project TimeGenerated, Computer, EventID, RenderedDescription
```
```sigma portable
title: Weak certificate mapping observed by the KDC
id: 6f1a5b52-3d4c-4a7e-9c1f-2b8e7d0a4c11
status: experimental
description: >
  A domain controller logged a certificate that authenticated a principal
  without a strong mapping (KB5014754). In Compatibility mode the KDC logs
  rather than blocks, which makes these the highest-signal, lowest-volume
  artefact of certificate-based impersonation available.
references:
  - https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a
author: huntbase.io
date: 2026/09/08
tags:
  - attack.privilege-escalation
  - attack.t1649
logsource:
  product: windows
  service: system
detection:
  kdc:
    Provider_Name: 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
    EventID:
      - 39
      - 41
  condition: kdc
falsepositives:
  - Certificates issued before the SID extension was enforced, during a migration window
level: high
```

## analyze-ca-requests
```sqlite target=cadb params=(since=window_start)
~~~yaml
source: Requests, RequestAttributes, Certificates (parsed CA database)
reads: [RequestID, SubmittedWhen, ResolvedWhen, RequesterName, CommonName, Disposition, DispositionMessage,
        AttributeName, AttributeValue, SerialNumber, CertificateHash, NotBefore, NotAfter, RevokedWhen]
verified: none
expected: >
  One row per request whose SAN or CommonName names a different principal than
  RequesterName, including denied ones. Enrollment-agent and web-server
  templates produce legitimate rows; the agent separates those.
silence: evidence_of_absence   # the CA database is complete for the window it holds — silence here means no such request
~~~
-- The ESC1 fingerprint, straight out of the CA database: the enrollee supplied a
-- subject or SAN naming a principal other than the authenticated requester.
-- Denied and failed requests (disposition 30/31) are kept deliberately — a failed
-- escalation attempt exists nowhere else, and the same actor usually retries
-- until a template accepts them.
--   Disposition: 9 pending | 20 issued | 21 revoked | 30 failed | 31 denied
SELECT r.RequestID,
       r.SubmittedWhen,
       r.ResolvedWhen,
       r.RequesterName,                      -- authenticated identity at the CA
       r.CommonName             AS RequestedCommonName,
       san.AttributeValue       AS RequestedSAN,
       tpl.AttributeValue       AS TemplateName,
       r.Disposition,
       r.DispositionMessage,
       c.SerialNumber,
       c.CertificateHash        AS Thumbprint,
       c.NotBefore,
       c.NotAfter,
       c.RevokedWhen
FROM Requests r
LEFT JOIN RequestAttributes san
       ON san.RequestID = r.RequestID
      AND lower(san.AttributeName) IN ('san', 'san:upn', 'subjectaltname')
LEFT JOIN RequestAttributes tpl
       ON tpl.RequestID = r.RequestID
      AND lower(tpl.AttributeName) IN ('certificatetemplate', 'requestcertificatetemplate')
LEFT JOIN Certificates c
       ON c.RequestID = r.RequestID
WHERE r.SubmittedWhen >= '{{since}}'
  AND coalesce(san.AttributeValue, r.CommonName) IS NOT NULL
  -- requester sAMAccountName, with the NETBIOS domain prefix stripped
  AND lower(coalesce(san.AttributeValue, r.CommonName)) NOT LIKE
      '%' || lower(substr(r.RequesterName, instr(r.RequesterName, '\') + 1)) || '%'
ORDER BY r.SubmittedWhen DESC
```

## esc1-candidates
if: `analyze-ca-requests.rows > 0`
then: → triage-candidates
else: → collection-coverage      # no rows may mean no abuse, or no data — decide which

## triage-candidates
```agent target=hunter
objective: >
  Decide, per candidate request, whether it is ESC1 abuse or authorized
  enrollment on behalf of another principal. For each row from
  analyze-ca-requests: resolve the template named in the request against
  enumerate-template-acls and state whether that template actually permits an
  enrollee-supplied subject without manager approval and carries a
  client-authentication EKU. Establish whether the requester was entitled to
  enroll at all. Check whether the requester is a computer account created inside
  the hunt window by a non-admin user (query-machine-account-creation), which is
  the AA26-237A pattern. Then look for the certificate being used: match
  SerialNumber/Thumbprint against query-certificate-logons, and treat any KDC 39
  or 41 event for the named identity (query-kdc-cert-mapping) as strong
  corroboration. Legitimate enrollment-agent and web-server enrollment will also
  show requester != subject — separate those out by template purpose and by
  whether the requester holds the Certificate Request Agent EKU.
context: [analyze-ca-requests, enumerate-template-acls, query-machine-account-creation,
          query-ca-audit-events, query-certificate-logons, query-kdc-cert-mapping]
tools: [cadb, ad, siem]
success_criteria: >
  A single verdict of malicious | suspicious | benign for the run, plus a per-request
  table naming template, requester, impersonated identity, disposition, and whether
  the certificate was subsequently used for PKINIT — each claim citing the step it
  came from. Requests whose template could not be resolved are reported as
  unresolved rather than folded into benign.
max_iterations: 12
```

## route-by-verdict
switch: `triage-candidates.verdict`
- "malicious"  → confirm-impersonation
- "suspicious" → verify-with-pki-owner
- default      → collection-coverage

## verify-with-pki-owner
```manual target=pki
For each unresolved or ambiguous request: confirm whether the enrollment was
authorized. Specifically — is the named template supposed to allow an
enrollee-supplied subject, who is intended to enroll in it, and was there a
change request covering the requester's activity in this window? Record the
answer; "nobody owns this template" is itself a finding for escalate-gap.
```
→ confirm-impersonation

## confirm-impersonation
if~: "one or more principals obtained, or attempted to obtain, a certificate that authenticates as a different and more privileged identity through a template that permits an enrollee-supplied subject — rather than authorized enrollment-on-behalf-of" (confidence: high, judge=hunter)
then: → contain
indeterminate: → manual-review
unavailable: → escalate-gap (blind_spot: no-template-owner)   # never close here
else: → close-with-notes

## contain

### revoke-issued-certificates
```action target=ca
~~~yaml
approval: required
track: containment
~~~
Revoke each certificate identified as abusive by serial number with reason
keyCompromise, then publish a CRL and delta CRL immediately — a revocation nobody
can fetch is not a revocation. Note the limit: revocation does not invalidate
tickets already obtained with the certificate, and Kerberos does not consult a
CRL, so revocation alone does not evict the actor.
```

### reset-impersonated-principals
```action target=ad
~~~yaml
approval: required
track: containment
~~~
For every identity that was impersonated: revoke sessions and reset the password
(twice for accounts with legacy replication concerns), and reset the account's
Kerberos state. If a domain controller's or a Domain Admin's identity was
obtained, treat this as full domain compromise: the KRBTGT reset and tier-0
recovery path apply, and that decision belongs to the incident commander, not to
this hunt.
```

### harden-template
```action target=ca
~~~yaml
approval: required
track: remediation
~~~
On the abused template: clear CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in
msPKI-Certificate-Name-Flag, or set PEND_ALL_REQUESTS in msPKI-Enrollment-Flag so
enrollment requires manager approval; remove client-authentication EKUs that the
template does not need; and restrict the Enroll/AutoEnroll rights to a scoped
group instead of Domain Users, Authenticated Users or Domain Computers. Then set
ms-DS-MachineAccountQuota to 0 and delegate computer-account creation, and move
the KDC to Full Enforcement of strong certificate mapping (KB5014754) once
KDC events 39/41 have been driven to zero.
```

## handoff-to-detection
```manual target=tier2
Hand the confirmed pattern to detection engineering as a standing rule: the CA
database comparison of requester against SAN/CommonName, scheduled per issuing CA,
plus alerting on KDC events 39/41 and on 4741 from non-delegated creators. Record
the abused template, the serials revoked, and the window covered, so the next run
of this hunt starts from a known-clean baseline.
```
→ end

## collection-coverage
if~: "every issuing CA in the forest was collected and parsed with committed and transaction-log rows for the whole hunt window, and the template configuration was enumerated successfully" (confidence: high, judge=hunter)
then: → close-no-evidence
indeterminate: → escalate-gap
unavailable: → escalate-gap (blind_spot: uncollected-ca)
else: → escalate-gap

## escalate-gap
```manual target=pki
Record what could not be examined and what it costs, then route it as a finding
rather than closing the hunt. Name, for each gap: the missing source (an issuing
CA that was never collected, a CA database whose retention had rolled, ADCS
auditing left disabled so 4886–4888 do not exist, KDC events unavailable because
the domain is below the KB5014754 logging baseline, or a template with no
identifiable owner to confirm intent); the question it left unanswerable; and the
business exposure of leaving it that way — certificate-based domain escalation is
persistent, survives password resets, and is invisible to every control that
watches passwords. Assign an owner and a date. Do not mark this hunt as finding
nothing: it did not look.
```
→ end

## manual-review
```manual target=tier2
Work the requests the agent could not decide. Pull the full request row and the
issued certificate from the CA database, compare the SAN against the requester's
own identity by hand, and check whether the certificate was used (4768 with
Certificate Information, KDC 39/41). Then either invoke containment or close with
notes — and if the block was missing template configuration rather than ambiguity,
route to escalate-gap instead.
```
→ end

## close-with-notes
```manual target=tier2
Record the benign explanation — most often enrollment-agent or web-server
enrollment where requester != subject is by design — and close. Add the template
and requester to the tuning list in analyze-ca-requests so the next run does not
re-surface them, and note the templates you confirmed as safe so the exclusion is
auditable rather than folklore.
```
→ end

## close-no-evidence
```manual target=tier2
Coverage was complete and no request named an identity other than its requester.
Close with the window, the CA hosts collected, and the row counts examined — this
is the negative result the hunt exists to be able to state.
```
→ end
