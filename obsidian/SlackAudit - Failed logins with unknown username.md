---
id: b62b5a97-41e5-47cb-9b90-aa079f65f0c0
name: SlackAudit - Failed logins with unknown username
description: |
  'This query shows failed login attempts where username is unknown.'
severity: Medium
requiredDataConnectors:
  - connectorId: SlackAuditAPI
    dataTypes:
      - SlackAudit_CL
tactics:
  - CredentialAccess
relevantTechniques:
  - T1110
query: |-
  ```kusto
  let lbtime = 24h;
  let lbperiod = 30d;
  let known_users = SlackAudit
  | where TimeGenerated > ago(lbperiod)
  | where DvcAction =~ 'user_login'
  | where isnotempty(SrcUserName)
  | summarize makeset(SrcUserName);
  SlackAudit
  | where TimeGenerated > ago(lbtime)
  | where DvcAction =~ 'user_login_failed'
  | where isnotempty(SrcUserName)
  | where SrcUserName !in (known_users)
  | project SrcUserName, SrcIpAddr
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

