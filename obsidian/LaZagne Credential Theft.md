---
id: f699a3e0-598e-4177-a110-c53c1bfeb897
name: LaZagne Credential Theft
description: |
  Use this query to locate processes executing credential theft activity, often LaZagne in ransomware compromises.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\nDeviceProcessEvents \n| where FileName =~ 'reg.exe'\n| where ProcessCommandLine has_all('save','hklm','sam')\n| project DeviceId, Timestamp, InitiatingProcessId, InitiatingProcessFileName, ProcessId, FileName, ProcessCommandLine\n```"
---

