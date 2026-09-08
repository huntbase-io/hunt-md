---
type: investigation
name: Kerberoasting hunt
labels:
  - hunt
  - attack.t1558.003    # Kerberoasting
tlp: green
severity: high
hypothesis: >
  Service accounts with weak passwords are being kerberoasted (RC4 TGS requests)
  from workstations outside the admin VLAN, for offline credential cracking.
hunt:                   # why this hunt exists and what happens after (SPEC §3.1)
  trigger: intel-report
  applicability: universal
  handoff: keep-as-periodic-hunt
  justification: >
    Service-account credentials are the shortest path from a foothold to
    domain-wide access; a cracked SPN password is reusable until rotated and
    invisible to MFA. Running this on a cadence is the control for that gap.
  assets: [service accounts, Active Directory]
references:
  - name: MITRE ATT&CK T1558.003
    url: https://attack.mitre.org/techniques/T1558/003/
parameters:
  lookback: { type: duration, default: "14d" }
targets:
  siem:   { category: siem, name: SIEM, telemetry: [identity] }   # 4769 is identity telemetry, wherever it's stored
  hunter: { agent: true,    name: Hunt agent }
  tier2:  { role: analyst,  name: Tier-2 analyst }
---

# Kerberoasting hunt

Hunt for RC4 TGS (event 4769, ticket encryption `0x17`) request bursts indicating
offline cracking of service-account credentials. A query gathers the candidates,
an agent triages burst-vs-legitimate, and the verdict routes response.

## enumerate-spn-requests
```kql target=siem params=(days=lookback)
~~~yaml
prevalence: { key: [Account], by: IpAddress, rare_below: 3 }   # an account roasted from many sources is the signal
baseline: { window: "{{days}}", compare: prior_equal_window }
~~~
SecurityEvent
| where TimeGenerated > ago({{days}})
| where EventID == 4769 and TicketEncryptionType == "0x17"
| summarize requests=count(), sources=dcount(IpAddress) by Account
```

## check-volume
if: `enumerate-spn-requests.rows > 0`
then: → triage
else: → end

## triage
```agent target=hunter
objective: >
  Determine whether the accounts show kerberoasting (burst enumeration, many
  distinct workstation sources, non-admin origin) or legitimate service
  behaviour. Return a single verdict per run.
context: [enumerate-spn-requests]
tools: [siem]
success_criteria: >
  A verdict of malicious | suspicious | benign, with the deciding evidence cited.
max_iterations: 6
```

## route-by-verdict
switch: `triage.verdict`
- "malicious"  → contain
- "suspicious" → manual-review
- default      → end

## contain
```action target=siem
~~~yaml
approval: required
~~~
Disable the flagged service accounts and force a credential rotation with a
strong, randomized password; review SPN assignments.
```
→ end

## manual-review
```manual target=tier2
Review the flagged accounts and their SPN usage; either invoke containment or
close with a tuning note for the burst threshold.
```
→ end
