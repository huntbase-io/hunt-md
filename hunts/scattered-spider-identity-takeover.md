---
type: investigation
name: Scattered Spider identity-takeover hunt
labels:
  - hunt
  - attack.t1621        # MFA request generation (push bombing)
  - attack.t1219        # remote access software
  - attack.t1114.002    # remote email collection
  - attack.t1484.002    # domain trust modification (rogue federation)
tlp: amber
severity: high
hypothesis: >
  Scattered Spider-style actors have socially engineered our helpdesk to reset
  credentials or MFA for one or more identities, registered attacker-controlled
  MFA devices, and are establishing persistence via commercial RMM tooling
  and/or a rogue federated identity provider — while monitoring our
  collaboration platforms for signs of detection.
references:
  - name: CISA AA23-320A — Scattered Spider (updated 2025-07-29)
    url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
parameters:
  lookback:  { type: duration, default: "10d" }
  rmm_tools: { type: string,   default: "anydesk.exe,screenconnect.client.exe,teamviewer.exe,splashtop.exe,fleetdeck_agent.exe,level.exe,tailscaled.exe,ngrok.exe,pulseway.exe" }
targets:
  # Abstract categories keep the hunt portable; the optional per-runtime binding
  # hint pins a concrete source when running on that platform.
  iam:    { category: iam,      name: Identity audit, huntbase: { product: azure_log_analytics } }
  siem:   { category: siem,     name: SIEM,           huntbase: { product: azure_log_analytics } }
  edr:    { category: endpoint, name: EDR,            huntbase: { product: msatp } }
  hunter: { agent: true,        name: Hunt agent }
  tier2:  { role: analyst,      name: Tier-2 analyst }
---

# Scattered Spider identity-takeover hunt

Hunts the AA23-320A intrusion chain: helpdesk social engineering → credential/MFA
resets, attacker MFA-device registration, RMM-based persistence, rogue identity
federation, and defender-surveillance of collaboration platforms. Deterministic
queries gather the signals in parallel; an agent correlates them per identity;
containment is gated behind approval, and indeterminate cases behind mandatory
human review.

## fan-out
parallel:
- → query-mfa-registrations
- → query-helpdesk-resets
- → query-rmm-installs
join: → correlate-identities

## query-mfa-registrations
```kql target=iam params=(days=lookback)
AuditLogs
| where TimeGenerated > ago({{days}})
| where OperationName in (
    "User registered security info",
    "User registered all required security info",
    "Register security information")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         IP    = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, IP, OperationName, ResultDescription
```

## query-helpdesk-resets
```kql target=iam params=(days=lookback)
AuditLogs
| where TimeGenerated > ago({{days}})
| where OperationName has_any ("Reset password", "Reset user password",
                               "Admin registered security info",
                               "Delete security info")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName),
         Initiator  = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, TargetUser, Initiator, OperationName
```

## query-rmm-installs
```kql target=edr params=(days=lookback, tools=rmm_tools)
DeviceProcessEvents
| where Timestamp > ago({{days}})
| where FileName in~ (split("{{tools}}", ","))
| where InitiatingProcessAccountName !in ("it-deploy-svc")   // sanctioned deployer
| summarize first_seen=min(Timestamp), hosts=make_set(DeviceName)
    by FileName, AccountName
```

## correlate-identities
```agent target=hunter
objective: >
  Correlate the MFA-registration, helpdesk-reset, and RMM-install results by
  identity and time. Flag identities matching the Scattered Spider chain: a
  helpdesk-initiated reset closely followed by MFA registration from an IP/ASN
  not previously associated with that user, and/or RMM tooling first appearing
  on that user's host in the same window. Distinguish genuine onboarding/refresh
  from takeover. Surface each flagged identity so downstream steps are scoped
  to it.
context: [query-mfa-registrations, query-helpdesk-resets, query-rmm-installs]
tools: [iam, siem, edr]
success_criteria: >
  Zero or more identities are flagged, each rated high | medium | low with the
  specific correlated events cited as evidence.
max_iterations: 10
```

## any-suspects
if: `correlate-identities.flagged > 0`
then: → pivot-persistence
else: → end

## pivot-persistence

### query-federation-changes
```kql target=iam params=(days=lookback)
AuditLogs
| where TimeGenerated > ago({{days}})
| where OperationName in ("Set federation settings on domain",
                          "Set domain authentication",
                          "Add unverified domain")
| project TimeGenerated, OperationName,
          Initiator = tostring(InitiatedBy.user.userPrincipalName),
          Detail    = tostring(TargetResources[0].displayName)
```

### query-ir-surveillance
```kql target=siem params=(days=lookback)
// Broad sweep of IR-topic mailbox/search activity; the agent correlates the
// hits against the flagged identities in `assess-takeover`.
OfficeActivity
| where TimeGenerated > ago({{days}})
| where Operation in ("SearchQueryPerformed", "MessagesRead", "MailItemsAccessed")
| where OfficeObjectId has_any ("incident", "compromise", "breach",
                                "scattered", "containment", "soc")
| project TimeGenerated, UserId, Operation, OfficeObjectId
```

## assess-takeover
if~: "taken together, the correlated evidence, federation changes, and IR-surveillance activity indicate an active identity takeover consistent with AA23-320A rather than benign IT activity" (confidence >= 0.75, judge=hunter)
then: → contain
indeterminate: → manual-review
else: → close-with-notes

## contain
```action target=edr
~~~yaml
approval: required
track: containment
~~~
For each flagged identity: revoke sessions, disable the account, remove the
attacker-registered MFA method, and isolate the associated host.
```
→ notify-out-of-band

## notify-out-of-band
```manual target=tier2
The actors monitor Teams/Slack/Exchange for IR discussion (AA23-320A) and may
join response calls. Coordinate containment via the out-of-band channel only;
do NOT discuss this incident on corporate collaboration platforms until the
flagged identities are contained.
```
→ end

## manual-review
```manual target=tier2
Review the evidence for each flagged identity. Verify the original helpdesk
interactions against ticket records and caller-verification logs, then either
invoke containment or close with notes.
```
→ end

## close-with-notes
```manual target=tier2
Record the benign explanation for the correlated events in the hunt log and
close. Consider tuning the sanctioned-deployer exclusion list if RMM noise was
the trigger.
```
→ end
