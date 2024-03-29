---
id: 440f5440-e452-4b19-a8a4-5e39b5676657
name: Trend Micro CAS - Ransomware threats
description: |
  'Query searches for ransomware threats.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroCAS
    dataTypes:
      - TrendMicroCAS
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: |-
  ```kusto
  TrendMicroCAS
  | where TimeGenerated > ago(24h)
  | where isnotempty(RansomwareName)
  | project DetectionTime, DstUserName, SrcFileName, RansomwareName
  | extend AccountCustomEntity = DstUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

