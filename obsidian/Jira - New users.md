---
id: aadc0945-a399-47ba-b285-c0c09ee06375
name: Jira - New users
description: |
  'Query searches for new users created.'
severity: Medium
requiredDataConnectors:
  - connectorId: JiraAuditAPI
    dataTypes:
      - JiraAudit
tactics:
  - Persistence
relevantTechniques:
  - T1078
query: |-
  ```kusto
  JiraAudit
  | where TimeGenerated > ago(24h)
  | where EventMessage =~ 'User created'
  | where ObjectItemTypeName =~ 'USER'
  | project EventCreationTime, UserName, SrcIpAddr, ObjectItemName, AssociatedItems
  | extend AccountCustomEntity = ObjectItemName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

