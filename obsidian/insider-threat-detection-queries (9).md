---
id: b2ac5ab0-52b0-4be5-9f3f-9d19b80bcc9e
name: insider-threat-detection-queries (9)
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
query: "```kusto\n// --------------------------------------------------------------------------------------------------------------------------- //\n//\n//Browse to Job Search website\n//\n// This query finds network communication to specific job search related URL\nlet partialRemoteUrlToDetect = pack_array (\n\"careerbuilder.com\",\n\"career\",\n\"glassdoor.com\",\n\"indeed.com\",\n\"internship\",\n\"job\",\n\"linkdin.com\",\n\"monster.com\",\n\"recruit\",\n\"resume\",\n\"simplyhired.com\"); \nDeviceNetworkEvents  \n| where Timestamp > ago(30d)\nand RemoteUrl has_any (partialRemoteUrlToDetect)\n```"
---

