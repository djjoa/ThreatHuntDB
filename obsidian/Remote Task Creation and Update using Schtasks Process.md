---
id: 9a5f5afa-8d85-11ec-b909-0242ac120002
name: Remote Task Creation/Update using Schtasks Process
description: "'The query detects a scheduled task, created/updated remotely, using the Schtasks process. \nThreat actors are using scheduled tasks for establishing persistence and moving laterally through the network.\nRef: https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html'\n"
severity: Low
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Persistence
relevantTechniques:
  - T1053
query: |-
  ```kusto
  SecurityEvent
  | where EventID == 4688 and NewProcessName == "C:\\Windows\\System32\\schtasks.exe" and CommandLine has " /s "
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, SubjectUserName, CommandLine
  ```
---

