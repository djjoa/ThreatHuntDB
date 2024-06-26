---
id: 6aae5700-79da-4b41-98cc-f77bf7489f01
name: Snowflake - Privileged users' source IP addresses
description: |
  'Query searches for privileged users' source IP addresses.'
severity: Medium
requiredDataConnectors:
  - connectorId: Snowflake
    dataTypes:
      - Snowflake
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto
  Snowflake
  | where TimeGenerated > ago(24h)
  | where QUERY_TYPE_s =~ 'SELECT'
  | summarize roles = makeset(ROLE_NAME_s) by TargetUsername
  | join(Snowflake
        | where TimeGenerated > ago(24h)
        | where EventType =~ 'LOGIN') on TargetUsername
  | project-away TargetUsername1
  | where roles has_any ('SECURITYADMIN', 'SYSADMIN', 'ACCOUNTADMIN')
  | summarize ip_lst = makeset(SrcDvcIpAddr) by TargetUsername
  | extend AccountCustomEntity = TargetUsername, IPCustomEntity = ip_lst
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

