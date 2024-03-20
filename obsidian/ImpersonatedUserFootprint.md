---
id: aeb65be9-7a40-409e-a227-56ebbcf33de4
name: ImpersonatedUserFootprint
description: |
  Microsoft Defender for Identity raises alert on suspicious Kerberos ticket, pointing to a potential overpass-the-hash attack.
  Once attackers gain credentials for a user with higher privileges, they will use the stolen credentials to sign into other devices and move laterally.
  This query finds related sign-in events following overpass-the-hash attack to trace the footprint of the impersonated user.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
      - DeviceLogonEvents
tactics:
  - Lateral movement
query: "```kusto\nAlertInfo\n| where ServiceSource =~ \"Microsoft Defender for Identity\"\n| where Title == \"Suspected overpass-the-hash attack (Kerberos)\"\n| extend AlertTime = Timestamp \n| join \n    (\n        AlertEvidence \n            | where EntityType == \"User\"\n    ) \n    on AlertId \n| distinct AlertTime,AccountSid \n| join kind=leftouter  \n    (\n        DeviceLogonEvents\n        | where LogonType == \"Network\" and ActionType == \"LogonSuccess\"\n        | extend LogonTime = Timestamp \n    )\n    on AccountSid \n| where LogonTime between (AlertTime .. (AlertTime + 2h))\n| project DeviceId , AlertTime , AccountName , AccountSid \n```"
---

