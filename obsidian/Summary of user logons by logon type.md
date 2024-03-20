---
id: d0f13bb9-e713-4f89-b610-1806326a1dea
name: Summary of user logons by logon type
description: "'Comparing succesful and nonsuccessful logon attempts can be used to identify attempts to move laterally within the \nenvironment with the intention of discovering credentials and sensitive data.'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - CredentialAccess
  - LateralMovement
relevantTechniques:
  - T1110
query: "```kusto\n\nSecurityEvent\n| where EventID in (4624, 4625)\n| where AccountType == 'User' \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Amount = count() by LogonTypeName\n| extend timestamp = StartTimeUtc\n```"
---

