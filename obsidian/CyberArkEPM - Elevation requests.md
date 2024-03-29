---
id: 20fc7ee2-5387-4c4c-8819-77fb7bfb8d2a
name: CyberArkEPM - Elevation requests
description: |
  'Query shows elevation requests.'
severity: Medium
requiredDataConnectors:
  - connectorId: CyberArkEPM
    dataTypes:
      - CyberArkEPM
tactics:
  - Execution
  - PrivilegeEscalation
relevantTechniques:
  - T1204
  - T1078
query: |-
  ```kusto
  CyberArkEPM
  | where TimeGenerated > ago(24h)
  | where EventSubType =~ 'ElevationRequest'
  | extend AccountCustomEntity = ActorUsername
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

