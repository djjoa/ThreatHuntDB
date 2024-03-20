---
id: 48b0ff4e-385c-4362-a184-612834a0b8c6
name: insider-threat-detection-queries (5)
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
query: "```kusto\n// --------------------------------------------------------------------------------------------------------------------------- //\n//\n//Personal Email Account\n//\n//This query searches for connections to specific webmail URLs\nlet webmailURLs = pack_array (\"mail.google.com\", \"mail.yahoo.com\", \"mail.protonmail.com\"); // Change or append additional webmail URLs\nDeviceNetworkEvents \n| where Timestamp > ago(30d)\nand RemoteUrl has_any (webmailURLs)\n```"
---
