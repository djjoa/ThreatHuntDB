---
id: 0a6e58fa-0689-418e-b05c-758c41664081
name: cobalt-strike
description: |
  This query was originally published in the threat analytics report, Ransomware continues to hit healthcare, critical services. There is also a related blog.
  In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques. The attackers would compromise a web-facing endpoint and employ tools such as Cobalt Strike to steal users' credentials.
  Cobalt Strike is commercial software used to conduct simulated threat campaigns against a target; however, malicious actors also use Cobalt Strike in real attacks. The software has a large range of capabilities, including credential theft.
  The following query identifies accounts that have logged on to compromised endpoints and have potentially had their credentials stolen.
  References:
  https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/
  https://www.cobaltstrike.com/
  https://attack.mitre.org/software/S0154/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
      - DeviceLogonEvents
tactics:
  - Initial access
  - Credential Access
  - Malware, component
query: "```kusto\n// Check for specific alerts\nAlertInfo\n// Attempts to clear security event logs.\n| where Title in(\"Event log was cleared\", \n// List alerts flagging attempts to delete backup files.\n\"File backups were deleted\", \n// Potential Cobalt Strike activity - Note that other threat activity can also \n//trigger alerts for suspicious decoded content\n\"Suspicious decoded content\", \n// Cobalt Strike activity\n\"\\'Atosev\\' malware was detected\", \n\"\\'Ploty\\' malware was detected\", \n\"\\'Bynoco\\' malware was detected\")\n| extend AlertTime = Timestamp\n| join AlertEvidence on AlertId \n| distinct DeviceName, AlertTime, AlertId, Title\n| join DeviceLogonEvents on $left.DeviceName == $right.DeviceName\n// Creating 10 day Window surrounding alert activity\n| where Timestamp < AlertTime +5d and Timestamp > AlertTime - 5d \n// Projecting specific columns\n| project Title, DeviceName, DeviceId, Timestamp, LogonType, AccountDomain, \nAccountName, AccountSid, AlertTime, AlertId, RemoteIP, RemoteDeviceName\n```"
---

