---
id: e68c3b84-7895-41d5-a9af-4ef776e82408
name: Imperva - Rare destination ports
description: |
  'Query searches for requests for rare destination ports.'
severity: Medium
requiredDataConnectors:
  - connectorId: ImpervaWAFCloudAPI
    dataTypes:
      - ImpervaWAFCloud
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: |-
  ```kusto
  ImpervaWAFCloud
  | where TimeGenerated > ago(24h)
  | summarize count() by DstIpAddr, DstPortNumber
  | top 20 by count_ asc
  | extend IPCustomEntity = DstIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

