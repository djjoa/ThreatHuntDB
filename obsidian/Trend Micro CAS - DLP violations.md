---
id: 001be88a-e98f-4e9a-ad30-62b9ad8222a5
name: Trend Micro CAS - DLP violations
description: |
  'Query searches for DLP violations by users.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroCAS
    dataTypes:
      - TrendMicroCAS
tactics:
  - Exfiltration
relevantTechniques:
  - T1048
query: |-
  ```kusto
  TrendMicroCAS
  | where TimeGenerated > ago(24h)
  | where isnotempty(TriggeredDlpTemplate)
  | project DetectionTime, DstUserName, SrcFileName, TriggeredDlpTemplate
  | extend AccountCustomEntity = DstUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

