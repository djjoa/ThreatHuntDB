---
id: eb5bf874-a707-4997-8d66-433cbf8b2f26
name: insider-threat-detection-queries (6)
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
      - DeviceNetworkEvents
tactics:
  - Initial access
  - Persistence
  - Exfiltration
query: "```kusto\n// --------------------------------------------------------------------------------------------------------------------------- //\n//\n//Access after Termination\n//\n// Look for any activity by a terminated employee account creating a\n// DeviceNetworkEvents after they were released\nlet TermAccount = 'FORMER_EMPLOYEE_NAME';  // Could also use SID\nlet ReleaseTime = datetime(\"01/16/2022 00:00:00\");\n//\nDeviceNetworkEvents \n| where InitiatingProcessAccountName =~ TermAccount\n| where Timestamp  > ReleaseTime\n| project Timestamp , DeviceName, InitiatingProcessAccountName\n| sort by Timestamp  desc\n```"
---

