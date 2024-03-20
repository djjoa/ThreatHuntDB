---
id: 351f7035-836c-4f4b-80bb-188220ba9215
name: Pivot from detections to related downloads
description: |
  Pivot from downloads detected by Windows Defender Antivirus to other files downloaded from the same sites.
  To learn more about the download URL info that is available and see other sample queries,.
  Check out this blog post: https://techcommunity.microsoft.com/t5/Threat-Intelligence/Hunting-tip-of-the-month-Browser-downloads/td-p/220454.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
      - DeviceFileEvents
query: "```kusto\nlet detectedDownloads =\n    DeviceEvents\n    | where ActionType == \"AntivirusDetection\" and isnotempty(FileOriginUrl)\n    | project Timestamp, FileOriginUrl, FileName, DeviceId,\n              ThreatName=tostring(parse_json(AdditionalFields).ThreatName)\n    // Filter out less severe threat categories on which we do not want to pivot\n    | where ThreatName !startswith \"PUA\"\n            and ThreatName !startswith \"SoftwareBundler:\" \n            and FileOriginUrl != \"about:internet\";\nlet detectedDownloadsSummary =\n    detectedDownloads\n    // Get a few examples for each detected Host:\n    // up to 4 filenames, up to 4 threat names, one full URL)\n    | summarize DetectedUrl=any(FileOriginUrl),\n                DetectedFiles=makeset(FileName, 4),\n                ThreatNames=makeset(ThreatName, 4)\n                by Host=tostring(parse_url(FileOriginUrl).Host);\n// Query for downloads from sites from which other downloads were detected by Windows Defender Antivirus\nDeviceFileEvents\n| where isnotempty(FileOriginUrl)\n| project FileName, FileOriginUrl, DeviceId, Timestamp,\n          Host=tostring(parse_url(FileOriginUrl).Host), SHA1 \n// Filter downloads from hosts serving detected files\n| join kind=inner(detectedDownloadsSummary) on Host\n// Filter out download file create events that were also detected.\n// This is needed because sometimes both of these events will be reported, \n// and sometimes only the AntivirusDetection event - depending on timing.\n| join kind=leftanti(detectedDownloads) on DeviceId, FileOriginUrl\n// Summarize a single row per host - with the machines count \n// and an example event for a missed download (select the last event)\n| summarize MachineCount=dcount(DeviceId), arg_max(Timestamp, *) by Host\n// Filter out common hosts, as they probably ones that also serve benign files\n| where MachineCount < 20\n| project Host, MachineCount, DeviceId, FileName, DetectedFiles, \n          FileOriginUrl, DetectedUrl, ThreatNames, Timestamp, SHA1\n| order by MachineCount desc \n```"
---

