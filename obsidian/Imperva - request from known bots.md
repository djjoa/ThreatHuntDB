---
id: 4cb3088c-445a-4a99-a90f-d583fe253a7d
name: Imperva - request from known bots
description: |
  'Query searches for requests from known bots.'
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
  | where ClientApp =~ 'Bot'
  | summarize count() by SrcIpAddr, NetworkApplicationProtocol
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

