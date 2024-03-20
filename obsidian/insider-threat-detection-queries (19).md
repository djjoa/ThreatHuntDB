---
id: a358a812-0e1b-4cbb-a91c-0bb1dbd3ea13
name: insider-threat-detection-queries (19)
description: |
  Intent:
  - Use MTP capability to look for insider threat potential risk indicators
  - Indicators would then serve as the building block for insider threat risk modeling in subsequent tools
  Definition of Insider Threat:
  "The potential for an individual who has or had authorized access to an organization's assets to use their access, either maliciously or unintentionally, to act in a way that could negatively affect the organization."
  This collection of queries describes the different indicators that could be used to model and look for patterns suggesting an increased risk of an individual becoming a potential insider threat.
  Note: no single indicator should be used as a lone determinant of insider threat activity, but should be part of an overall program to understand the increased risk to your organization's critical assets. This in turn is used to feed an investigation by a formal insider threat program to look at the context associated with the whole person to understand the implication of a set of indicators.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
      - DeviceLogonEvents
tactics:
  - Initial access
  - Persistence
  - Exfiltration
query: "```kusto\n// --------------------------------------------------------------------------------------------------------------------------- //\n//Backdoor Account Usage\n//\n//Look for newly created local accounts that log in within 30 minutes\nDeviceEvents\n| where ActionType == \"UserAccountCreated\"\n| project DeviceId , AccountName, Start=Timestamp\n| join kind=inner\n    (\n    DeviceLogonEvents \n    | project AccountName, DeviceId, End=Timestamp\n    ) on AccountName \n| where (End - Start) between (0min.. 30min)\n//Reference https://github.com/microsoft/Microsoft-threat-protection-Hunting-Queries/blob/master/Persistence/Create%20account.txt \n```"
---

