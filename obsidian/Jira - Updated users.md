---
id: d208b406-1509-455c-8c7d-7ffe2f893f24
name: Jira - Updated users
description: |
  'Query searches for updated users.'
severity: Medium
requiredDataConnectors:
  - connectorId: JiraAuditAPI
    dataTypes:
      - JiraAudit
tactics:
  - PrivilegeEscalation
  - Impact
relevantTechniques:
  - T1531
  - T1078
query: |-
  ```kusto
  JiraAudit
  | where TimeGenerated > ago(24h)
  | where EventMessage =~ 'User updated'
  | project EventCreationTime, ObjectItemName, ChangedValues, AssociatedItems
  | extend AccountCustomEntity = ObjectItemName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

