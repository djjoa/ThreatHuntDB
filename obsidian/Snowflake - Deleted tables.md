---
id: 5736df91-ec99-4fb2-b162-a17607d20ee8
name: Snowflake - Deleted tables
description: |
  'Query searches for deleted tables.'
severity: Medium
requiredDataConnectors:
  - connectorId: Snowflake
    dataTypes:
      - Snowflake
tactics:
  - Impact
relevantTechniques:
  - T1485
query: |-
  ```kusto
  Snowflake
  | where TimeGenerated > ago(24h)
  | where QUERY_TYPE_s =~ 'DROP'
  | where QUERY_TEXT_s has 'table'
  | where EXECUTION_STATUS_s =~ 'SUCCESS'
  | extend AccountCustomEntity = TargetUsername
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

