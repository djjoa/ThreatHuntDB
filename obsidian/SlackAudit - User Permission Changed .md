---
id: 7adbe474-debf-47c2-9d76-49efd4d2953b
name: SlackAudit - User Permission Changed
description: |
  'Query searches for user permissions changes events.'
severity: Medium
requiredDataConnectors:
  - connectorId: SlackAuditAPI
    dataTypes:
      - SlackAudit_CL
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078
query: |-
  ```kusto
  SlackAudit
  | where TimeGenerated > ago(24h)
  | where DvcAction in~ ('user_added_to_usergroup', 'user_removed_from_usergroup')
  | extend AccountCustomEntity = SrcUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
---

