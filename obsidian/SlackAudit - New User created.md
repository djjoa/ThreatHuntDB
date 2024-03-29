---
id: d65400c2-50a3-46cc-b3e6-1cb72b953e72
name: SlackAudit - New User created
description: |
  'This query shows new user created.'
severity: Medium
requiredDataConnectors:
  - connectorId: SlackAuditAPI
    dataTypes:
      - SlackAudit_CL
tactics:
  - Persistence
relevantTechniques:
  - T1136
query: |-
  ```kusto
  SlackAudit
  | where TimeGenerated > ago(24h)
  | where DvcAction =~ 'user_created'
  | extend AccountCustomEntity = SrcUserName
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

