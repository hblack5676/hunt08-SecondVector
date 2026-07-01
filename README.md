# Threat Hunt Report: Hunt 08 - Second Vector

## Overview

This investigation was conducted in Microsoft Defender XDR and Microsoft Sentinel following an Identity Protection alert generated for a suspicious sign-in against a finance employee.

The objective of the investigation was to determine:

- Whether the account was compromised
- How the attacker authenticated
- What actions were performed after compromise
- Whether data theft occurred
- Whether Business Email Compromise (BEC) activity occurred
- Whether persistence mechanisms were established

---

# MITRE ATT&CK Techniques

| Technique | Description |
|-----------|-------------|
| T1078 | Valid Accounts |
| T1114 | Email Collection |
| T1114.003 | Email Forwarding Rule |
| T1539 | Steal Web Session Cookie |
| T1119 | Automated Collection |
| T1566 | Phishing / Business Email Compromise |
| T1020 | Automated Exfiltration |

---

# Incident Summary

An Entra ID Identity Protection alert identified suspicious authentication activity against the account:

```
m.smith@lognpacific.org
```

The investigation determined the account had been successfully compromised.

Following authentication, the attacker:

- Queried Microsoft Graph
- Performed identity reconnaissance
- Read historical finance emails
- Downloaded sensitive documents
- Created malicious inbox rules
- Forwarded emails outside the organization
- Sent fraudulent payment requests through multiple communication channels

The incident escalated from a low-severity identity alert into a confirmed Business Email Compromise.

---

# Environment

- Microsoft Defender XDR
- Microsoft Sentinel
- Microsoft Entra ID
- Microsoft Graph
- Exchange Online
- Microsoft Teams
- SharePoint / OneDrive
- Kusto Query Language (KQL)

---

# Initial Alert

## Compromised User
```
m.smith@lognpacific.org
```
## Suspicious IP
```
103.69.224.136
```
## Client Operating System
```
Linux
```
## Authentication
```
singleFactorAuthentication
```
Although MFA was enforced, the attacker successfully authenticated using a valid session.

---

# Phase 1 — Identity Investigation

The investigation began by reviewing successful sign-ins associated with the malicious IP.

Example query:

```kql
AADSignInEventsBeta
| where IPAddress == "103.69.224.136"
```

Important findings included:

- Successful authentication
- Linux client
- Microsoft Graph access
- Anonymous infrastructure
- OAuth token issuance

---

# Phase 2 — Microsoft Graph Reconnaissance

The attacker immediately began enumerating the victim's identity.

One of the earliest requests queried:

```
userRegistrationDetails
```

This endpoint reveals information regarding:

- MFA capability
- Registration status
- Authentication methods

This indicates the attacker was assessing the account's security posture before continuing.

---

# Phase 3 — Mailbox Reconnaissance

The attacker searched historical finance conversations.

A particularly important email thread was:

```
Q1 Vendor Payment Schedule - Review Required
```

This thread predated the compromise by several months.

Rather than searching random emails, the attacker intentionally reviewed finance procedures before attempting fraud.

---

# Phase 4 — Business Email Compromise

The attacker created and transmitted a fraudulent payment request.

Subject:
```
Re: Updated Banking Details - Pacific IT Monthly
```
Recipient:
```
j.reynolds@lognpacific.org
```
The attacker also repeated the same request using:
```
Microsoft Teams
```
Using multiple communication channels increases the likelihood that the victim responds before verifying legitimacy.

---

# Phase 5 — Inbox Rule Persistence

Two malicious inbox rules were created.

## Rule 1

Name
```
Invoice Processing
```
Action
```
Move messages from j.reynolds@lognpacific.org
to Archive
```

Purpose:

Hide replies from the finance employee so the victim never sees objections or payment verification requests.

---

## Rule 2

Name
```
Backup Copy
```
Forward destination
```
merovingian1337@proton.me
```
Purpose:

Automatically exfiltrate future email conversations outside the organization.

---

# Phase 6 — File Collection

Normal user behavior consisted primarily of:

- FileAccessed
- PageViewed
- ListViewed

These operations indicate users are viewing documents inside Microsoft 365.

During the attack, the following operation was observed:

```
FileDownloaded
```

Unlike FileAccessed, this operation indicates copies were removed from Microsoft 365.

Downloaded files included:

```
VPN-Access-Credentials.txt
Vendor-Banking-Details.txt
book.xlsx
```

Only three files were downloaded.

This suggests:

- targeted collection
- deliberate theft
- high-value document selection

rather than indiscriminate mass collection.

---

# Interesting Artifact

One file particularly increased the severity of the incident:

```
VPN-Access-Credentials.txt
```

Compromise of VPN credentials expands attacker access beyond Microsoft 365 and potentially into the internal corporate network.

---

# Timeline

| Time | Activity |
|-------|----------|
| Identity Protection Alert | Triggered |
| Successful Sign-in | Linux client |
| Microsoft Graph Enumeration | userRegistrationDetails |
| Mailbox Reconnaissance | Historical finance emails |
| Fraud Email Sent | Banking details |
| Teams Follow-up | Payment request repeated |
| Inbox Rules Created | Persistence established |
| File Downloads | Sensitive documents collected |

---

# Indicators of Compromise

## User

```
m.smith@lognpacific.org
```

## External IP

```
103.69.224.136
```

## External Email

```
merovingian1337@proton.me
```

## Fraud Subject

```
Re: Updated Banking Details - Pacific IT Monthly
```

## Recon Subject

```
Q1 Vendor Payment Schedule - Review Required
```

---

# MITRE Mapping

| Activity | ATT&CK |
|-----------|---------|
| Valid Sign-in | T1078 |
| Microsoft Graph Enumeration | Discovery |
| Mailbox Recon | T1114 |
| Inbox Rules | T1114.003 |
| Email Forwarding | Persistence |
| Teams Messaging | Collection |
| File Downloads | T1119 |
| Credential Discovery | Discovery |

---

# Lessons Learned

This investigation demonstrates how a seemingly low-severity identity alert can quickly evolve into a confirmed Business Email Compromise.

Key observations included:

- Successful authentication using a valid session
- Identity reconnaissance through Microsoft Graph
- Historical finance email collection
- Fraudulent payment requests
- Teams follow-up to reinforce the scam
- Malicious inbox rules for persistence
- External email forwarding
- Targeted theft of sensitive files

The investigation required correlating telemetry across multiple Microsoft 365 services including Entra ID, Microsoft Graph, Exchange Online, SharePoint, Teams, and Microsoft Defender XDR.

---

# Skills Demonstrated

- Microsoft Defender XDR
- Microsoft Sentinel
- Microsoft Entra ID Investigation
- Microsoft Graph Hunting
- Exchange Online Forensics
- Microsoft Teams Investigation
- SharePoint Investigation
- Business Email Compromise Investigation
- Threat Hunting
- Kusto Query Language (KQL)
- MITRE ATT&CK Mapping
- Incident Response
