---
id: c862b799-aced-40fd-b600-d85d06d3505c
name: Bitglass - Risky users
description: |
  'Query searches for risky users.'
severity: Medium
requiredDataConnectors:
  - connectorId: Bitglass
    dataTypes:
      - Bitglass
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto
  Bitglass
  | where TimeGenerated > ago(24h)
  | where EventType =~ 'swgweb'
  | where Action =~ 'block'
  | summarize count() by User
  | extend AccountCustomEntity = User
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

