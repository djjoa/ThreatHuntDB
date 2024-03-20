---
id: 61ca48de-5973-4f9d-8f9c-e24776b6ba45
name: Ransomware hits healthcare - Robbinhood activity
description: |
  Find distinct evasion and execution activities.
  Associated with the Robbinhood ransomware campaign.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d) \n| where InitiatingProcessFileName =~ \"winlogon.exe\"  \n| where FileName == \"cmd.exe\" and ProcessCommandLine has_any(\"taskkill\", \"net\", \n\"robbin\", \"vssadmin\", \"bcdedit\", \"wevtutil\")\n```"
---

