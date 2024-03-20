---
id: 52c9e90b-84f4-4e2d-ae3d-eef85e8aa069
name: AV Detections with Source
description: |
  This query shows the source of the AV detections (e.g., the website the file was downloaded from etc.).
  Get the list of AV detections.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
      - DeviceFileEvents
query: "```kusto\nlet avDetections =\nDeviceEvents\n| where ActionType == \"AntivirusDetection\" and isnotempty(MD5)\n| extend ParsedFields=parse_json(AdditionalFields)\n| project Timestamp, DeviceName, ThreatName=tostring(ParsedFields.ThreatName), FileName, FolderPath, MD5;\n//Get a list of file creations\nlet fileCreations =\nDeviceFileEvents \n| where (isnotempty(FileOriginReferrerUrl) or isnotempty(FileOriginUrl)) and isnotempty(MD5)\n| project MD5, FileOriginUrl, FileOriginReferrerUrl, InitiatingProcessFileName, InitiatingProcessParentFileName;\n//Join the file creations and AV detections on the MD5 of the file\navDetections | join kind=inner (fileCreations) on MD5\n| project-away MD51 //Remove the duplicated MD5 field\n| sort by Timestamp desc \n```"
---

