---
id: ef815b70-e6f6-427b-ac9f-56d73472c4c3
name: SlackAudit - Users joined channels without invites
description: |
  'Query searches for users which joined channels without invites.'
severity: Medium
requiredDataConnectors:
  - connectorId: SlackAuditAPI
    dataTypes:
      - SlackAudit_CL
tactics:
  - InitialAccess
  - Persistence
relevantTechniques:
  - T1133
query: |-
  ```kusto
  SlackAudit
  | where TimeGenerated > ago(24h)
  | where DvcAction =~ 'user_channel_join'
  | where DetailsType =~ 'JOINED'
  | extend AccountCustomEntity = SrcUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
---

