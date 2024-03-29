---
id: 7b17d83a-7a88-4867-accf-494736bcec50
name: OCI - Updated instances
description: |
  'Query searches for updated instances.'
severity: Medium
requiredDataConnectors:
  - connectorId: OracleCloudInfrastructureLogsConnector
    dataTypes:
      - OCILogs
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1578
query: |-
  ```kusto
  OCILogs
  | where TimeGenerated > ago(24h)
  | where data_eventName_s =~ 'UpdateInstance'
  | extend AccountCustomEntity = data_definedTags_Oracle_Tags_CreatedBy_s
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

