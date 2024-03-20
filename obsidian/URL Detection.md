---
id: be220c78-843b-43c5-b638-dc9d10100c75
name: URL Detection
description: |
  This query finds network communication to specific URL.
  Please note that in line #7 it filters RemoteUrl using has operator, which looks for a "whole term" and runs faster.
  Example: RemoteUrl has "microsoft" matches "www.microsoft.com" but not "microsoftonline.com".
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
query: "```kusto\nlet partialRemoteUrlToDetect = \"microsoft.com\"; // Change this to a URL you'd like to find machines connecting to\nDeviceNetworkEvents  \n| where Timestamp > ago(7d)\nand RemoteUrl has partialRemoteUrlToDetect // Can be changed to \"contains\" operator as explained above\n| project Timestamp, DeviceName, DeviceId, ReportId\n| top 100 by Timestamp desc\n```"
---

