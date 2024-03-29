---
id: 7fc83c11-1d80-4d1e-9d4b-4f48bbf77abe
name: Sentinel One - Agent not updated
description: |
  'Query shows agent which are not updated to the latest version.'
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
  //Latest agent version can be checked in Management Console>Sentinels>Packages
  let upd_ver = dynamic(['21.7.4.1043', '21.7.4.5853', '21.10.3.3', '21.12.1.5913']);
  SentinelOne
  | where TimeGenerated > ago(24h)
  | where EventType =~ 'Agents.'
  | where AgentVersion !in (upd_ver)
  | extend HostCustomEntity = ComputerName
  ```
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostCustomEntity
---

