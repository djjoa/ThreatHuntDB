---
id: 95db9b9c-7a12-4c0b-85c8-1c54f67c5ac7
name: Potential ransomware activity related to Cobalt Strike
description: |
  Use this query to look for alerts related to suspected ransomware and Cobalt Strike activity, a tool used in numerous ransomware campaigns
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
      - DeviceLogonEvents
tactics:
  - Ransomware
query: "```kusto\n// Look for sc.exe disabling services\nAlertInfo \n// Attempts to clear security event logs. \n| where Title in(\"Event log was cleared\", \n// List alerts flagging attempts to delete backup files. \n\"File backups were deleted\", \n// Potential Cobalt Strike activity - Note that other threat activity can also \n// trigger alerts for suspicious decoded content \n\"Suspicious decoded content\", \n// Cobalt Strike activity \n\"\\'Atosev\\' malware was detected\", \n\"\\'Ploty\\' malware was detected\", \n\"\\'Bynoco\\' malware was detected\",\n\"\\'Cobaltstrike\\' malware was detected\",\n\"Echo command over pipe on localhost\",\n\"Known attack framework activity was observed\",\n\"An active \\'Cobaltstrike\\' malware was detected\",\n\"Suspicious \\'CobaltStrike\\' behavior was prevented\",\n\"Suspicious process launch by Rundll32.exe\") \n| extend AlertTime = Timestamp | distinct AlertTime, AlertId, Title \n| join AlertEvidence on $left.AlertId == $right.AlertId\n| summarize by DeviceId, AlertTime, Title, AlertId\n// Get device IDs\n| join DeviceLogonEvents on $left.DeviceId == $right.DeviceId \n// Creating 10 day Window surrounding alert activity \n| where Timestamp < AlertTime +5d and Timestamp > AlertTime - 5d // Projecting specific columns \n| project Title, DeviceName, DeviceId, Timestamp, LogonType, AccountDomain, AccountName, AccountSid, AlertTime, AlertId, RemoteIP, RemoteDeviceName\n```"
---

