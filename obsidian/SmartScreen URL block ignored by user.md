---
id: 172e5bee-9298-4c59-bd2a-e96d87e8e6d8
name: SmartScreen URL block ignored by user
description: |
  Query for SmartScreen URL blocks, where the user has decided to run the malware nontheless.
  An additional optional filter is applied to query only for cases where Microsoft Edge has downloaded a file shortly after the ignored block.
  Read more about SmartScreen here: https://docs.microsoft.com/windows/security/threat-protection/windows-defender-smartscreen/windows-defender-smartscreen-overview.
  Data availability: These events are available only on Windows 10 version 1703 and onwards.
  Tags: #SmartScreen.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
      - DeviceFileEvents
query: "```kusto\nlet minTimeRange = ago(7d);\nlet smartscreenUrlBlocks = \n    DeviceEvents\n    | where ActionType == \"SmartScreenUrlWarning\" and Timestamp > minTimeRange\n            // Filter out SmartScreen test URLs under https://demo.smartscreen.msft.net/\n            and RemoteUrl !startswith \"https://demo.smartscreen.msft.net/\" \n    | extend ParsedFields=parse_json(AdditionalFields)\n    | project Timestamp, DeviceName, BlockedUrl=RemoteUrl, Recommendation=tostring(ParsedFields.Recommendation), Experience=tostring(ParsedFields.Experience), ActivityId=tostring(ParsedFields.ActivityId);\n// Query for UserDecision events - each one means the user has decided to ignore the warning and run the app.\nlet userIgnoredWarning=\n    DeviceEvents\n    | where ActionType == \"SmartScreenUserOverride\" and Timestamp > minTimeRange\n    | project DeviceName, ActivityId=extractjson(\"$.ActivityId\", AdditionalFields, typeof(string));\n// Join the block and user decision event using an ActivityId\nlet ignoredBlocks = smartscreenUrlBlocks | join kind=leftsemi (userIgnoredWarning) on DeviceName, ActivityId | project-away ActivityId;\n// Optional additional filter - look only for cases where a file was downloaded from Microsoft Edge following the URL block being ignored \nlet edgeDownloads = \n    DeviceFileEvents\n    | where Timestamp > minTimeRange and InitiatingProcessFileName =~ \"browser_broker.exe\"\n    | summarize (DownloadTime, SHA1) = argmax(Timestamp, SHA1) by FileName, DeviceName, FileOriginUrl, FileOriginReferrerUrl;\nignoredBlocks\n| join kind=inner (edgeDownloads) on DeviceName\n| where DownloadTime - Timestamp between (0min .. 2min)\n| project-away DeviceName1\n```"
---

