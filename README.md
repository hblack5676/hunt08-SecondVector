# Threat Hunt Report: Hunt 08 - Second Vector

**Participant:** Hugh Black  
**Date:** June 2026  
**Environment:** Microsoft Defender XDR, Microsoft Sentinel / Log Analytics  
**Scenario:** Low-severity Entra ID Protection alert against finance user `m.smith@lognpacific.org`

## Platforms and Tools Used

- Microsoft Defender XDR
- Microsoft Sentinel / Log Analytics
- Microsoft Entra ID Protection
- Microsoft 365 Audit Logs
- Microsoft Graph Activity Logs
- Kusto Query Language (KQL)

## Executive Summary

A low-severity anonymous IP sign-in alert against finance user `m.smith@lognpacific.org` was investigated. The alert was initially rated low, but hunting revealed successful authentication from an anonymous IP, Microsoft Graph activity, mailbox reconnaissance, malicious inbox rules, file downloads, and a payment-redirection fraud attempt.

## Key Findings

- Compromised account: `m.smith@lognpacific.org`
- Suspicious IP: `103.69.224.136`
- Location: Amsterdam, Netherlands
- Client OS: Linux
- Authentication requirement: `singleFactorAuthentication`
- Fraud target: `j.reynolds@lognpacific.org`
- External forwarding address: `merovingian1337@proton.me`
- Malicious inbox rule: `Invoice Processing`
- External forwarding rule: `Backup Copy`
- Downloaded files:
  - `VPN-Access-Credentials.txt`
  - `Vendor-Banking-Details.txt`
  - `book.xlsx`

## Timeline and Queries Used

### 1. Identify the Flagged Account

```kql
AADSignInEventsBeta
| where IPAddress == "103.69.224.136"
| project Timestamp, AccountUpn, IPAddress, OSPlatform, ErrorCode
