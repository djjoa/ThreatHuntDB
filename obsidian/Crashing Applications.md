---
id: 53b250f6-c684-4932-aca9-a06045a962d6
name: Crashing Applications
description: |
  This query identifies crashing processes based on parameters passed
  to werfault.exe and attempts to find the associated process launch
  from DeviceProcessEvents.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
  - Misconfiguration
query: "```kusto\nDeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName =~ 'werfault.exe'\n| project CrashTime = Timestamp, DeviceId, WerFaultCommand = ProcessCommandLine, CrashProcessId = extract(\"-p ([0-9]{1,5})\", 1, ProcessCommandLine) \n| join kind= inner hint.strategy=shuffle DeviceProcessEvents on DeviceId\n| where CrashProcessId == ProcessId and Timestamp between (datetime_add('day',-1,CrashTime) .. CrashTime)\n| project-away ActionType\n| project-rename ProcessStartTimestamp = Timestamp\n```"
---

