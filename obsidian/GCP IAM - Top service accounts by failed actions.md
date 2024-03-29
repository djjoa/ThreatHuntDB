---
id: 27234847-8d3f-4d33-a3ef-5d3ec2575154
name: GCP IAM - Top service accounts by failed actions
description: |
  'Query searches for service accounts with top failed actions count.'
severity: Low
requiredDataConnectors:
  - connectorId: GCPIAMDataConnector
    dataTypes:
      - GCP_IAM
tactics:
  - Discovery
relevantTechniques:
  - T1580
  - T1526
query: |-
  ```kusto
  GCP_IAM
  | where TimeGenerated > ago(24h)
  | extend result = parse_json(todynamic(PayloadAuthorizationinfo))[0]['granted']
  | where result =~ 'false'
  | summarize count() by ResourceLabelsProjectId
  | top 10 by count_
  | extend AccountCustomEntity = ResourceLabelsProjectId
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
---

