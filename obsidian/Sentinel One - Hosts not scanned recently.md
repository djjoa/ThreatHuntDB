---
id: e45ff570-e8a6-4f8e-9c08-7ee92ef86060
name: Sentinel One - Hosts not scanned recently
description: |
  'Query searches for hosts wich were not scanned recently.'
severity: Medium
requiredDataConnectors:
  - connectorId: SentinelOne
    dataTypes:
      - SentinelOne
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1070
query: |-
  ```kusto
  let scanned_agents = SentinelOne
  | where TimeGenerated > ago(24h)
  | where ActivityType == 92
  | order by TimeGenerated
  | summarize makeset(DataComputerName);
  SentinelOne
  | where TimeGenerated > ago(24h)
  | where EventType =~ 'Agents.'
  | where ComputerName !in (scanned_agents)
  | extend HostCustomEntity = ComputerName
  ```
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostCustomEntity
---

