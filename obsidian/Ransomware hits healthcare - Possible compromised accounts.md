---
id: f4506828-36f5-4668-8203-de062963be63
name: Ransomware hits healthcare - Possible compromised accounts
description: |
  Identify accounts that have logged on to affected endpoints.
  Check for specific alerts.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
      - DeviceLogonEvents
query: "```kusto\nAlertInfo \n| where Timestamp > ago(7d)\n// Attempts to clear security event logs.\n| where Title in(\"Event log was cleared\", \n// List alerts flagging attempts to delete backup files.\n\"File backups were deleted\", \n// Potential Cobalt Strike activity - Note that other threat activity can also \n// trigger alerts for suspicious decoded content\n\"Suspicious decoded content\", \n// Cobalt Strike activity\n\"'Atosev' malware was detected\", \n\"'Ploty' malware was detected\", \n\"'Bynoco' malware was detected\")\n| extend AlertTime = Timestamp\n| join AlertEvidence on AlertId \n| distinct DeviceName, AlertTime, AlertId, Title\n| join DeviceLogonEvents on DeviceName\n// Creating 10 day Window surrounding alert activity\n| where Timestamp < AlertTime +5d and Timestamp > AlertTime - 5d \n// Projecting specific columns\n| project Title, DeviceName, DeviceId, Timestamp, LogonType, AccountDomain, \nAccountName, AccountSid, AlertTime, AlertId, RemoteIP, RemoteDeviceName\n```"
---

