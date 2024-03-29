---
id: 660e92b5-1ef6-471f-b753-44a34af82c41
name: Sentinel One - Alert triggers (files, processes, strings)
description: |
  'Query shows alert triggers (e.g. files, processes, etc.).'
severity: High
requiredDataConnectors:
  - connectorId: SentinelOne
    dataTypes:
      - SentinelOne
tactics:
  - InitialAccess
relevantTechniques:
  - T1204
query: |-
  ```kusto
  SentinelOne
  | where TimeGenerated > ago(24h)
  | where ActivityType == 3608
  | order by EventCreationTime
  | extend trigger = extract(@'Alert created for\s+(.*?)\sfrom Custom', 1, EventOriginalMessage)
  | extend MalwareCustomEntity = trigger
  ```
entityMappings:
  - entityType: Malware
    fieldMappings:
      - identifier: Name
        columnName: MalwareCustomEntity
---

