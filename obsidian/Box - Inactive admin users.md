---
id: d8ef8d5c-97f3-4552-afca-75d44339fa8f
name: Box - Inactive admin users
description: |
  'Query shows inactive admin accounts (admin users which last login time is more than 30 days).'
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
  let active_admins = BoxEvents
  | where TimeGenerated between (ago(7d) .. ago(1d))
  | where EventType =~ 'ADMIN_LOGIN'
  | summarize makeset(SourceLogin);
  let inactive_admins = BoxEvents
  | where TimeGenerated between (ago(30d) .. ago(7d))
  | where EventType =~ 'ADMIN_LOGIN'
  | where SourceLogin !in (active_admins)
  | summarize makeset(SourceLogin);
  BoxEvents
  | where TimeGenerated > ago(7d)
  | where EventType =~ 'ADMIN_LOGIN'
  | where SourceLogin !in (active_admins)
  | where SourceLogin in (inactive_admins)
  | summarize LastLoginTime = max(TimeGenerated) by SourceLogin
  | project LastLoginTime, SourceLogin
  | extend AccountCustomEntity = SourceLogin
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
---
