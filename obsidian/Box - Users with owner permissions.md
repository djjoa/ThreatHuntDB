---
id: 09fee766-d5ba-4e8c-8e9e-363915aee1f4
name: Box - Users with owner permissions
description: |
  'Query shows users with newly added owner permissions.'
severity: Medium
requiredDataConnectors:
  - connectorId: BoxDataConnector
    dataTypes:
      - BoxEvents_CL
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078
query: |-
  ```kusto
  BoxEvents
  | where TimeGenerated > ago(24h)
  | where EventType =~ 'COLLABORATION_ROLE_CHANGE'
  | where AdditionalDetailsRole =~ 'Owner'
  | project TimeGenerated, AccessibleByLogin, FileDirectory
  | extend AccountCustomEntity = AccessibleByLogin
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
---

