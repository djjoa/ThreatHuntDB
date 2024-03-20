---
id: 333ad16e-620b-4f36-af3b-da33f8d16cc2
name: SmartScreen app block ignored by user
description: |
  Query for SmartScreen application blocks on files with "Malicious" reputation, where the user has decided to run the malware nontheless.
  Read more about SmartScreen here: https://docs.microsoft.com/windows/security/threat-protection/windows-defender-smartscreen/windows-defender-smartscreen-overview.
  Data availability: These events are available only on Windows 10 version 1703 and onwards.
  Tags: #SmartScreen.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
query: "```kusto\nlet minTimeRange = ago(7d);\nlet smartscreenAppBlocks = \n    DeviceEvents\n    | where ActionType == \"SmartScreenAppWarning\" and Timestamp > minTimeRange\n            // Filter out SmartScreen test files downloaded from https://demo.smartscreen.msft.net/\n            and not (FileName startswith \"knownmalicious\" and FileName endswith \".exe\")\n    | extend ParsedFields=parse_json(AdditionalFields)\n    | project Timestamp, DeviceName, BlockedFileName=FileName, SHA1, Experience=tostring(ParsedFields.Experience), ActivityId=tostring(ParsedFields.ActivityId), InitiatingProcessFileName;\n// Query for UserDecision events - each one means the user has decided to ignore the warning and run the app.\nlet userIgnoredWarning=\n    DeviceEvents\n    | where ActionType == \"SmartScreenUserOverride\" and Timestamp > minTimeRange\n    | project DeviceName, ActivityId=extractjson(\"$.ActivityId\", AdditionalFields, typeof(string));\n// Join the block and user decision event using an ActivityId\nlet ignoredBlocks = \n\tsmartscreenAppBlocks\n\t| join kind=leftsemi (userIgnoredWarning) on DeviceName, ActivityId\n\t| project-away ActivityId;\nignoredBlocks\n// Select only blocks on \"Malicious\" files.\n// To hunt over Unknown/Untrusted files, remove the following where clause, but then you might want to join with additional signals.\n| where Experience == \"Malicious\"\n```"
---

