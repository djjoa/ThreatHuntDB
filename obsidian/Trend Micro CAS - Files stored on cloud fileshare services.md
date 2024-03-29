---
id: 765f1769-cbe2-4c1a-a708-1769c2c48d79
name: Trend Micro CAS - Files stored on cloud fileshare services
description: |
  'Query searches for stored on cloud fileshare services.'
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
  | where EventCategoryType in~ ('sharepoint', 'onedrive', 'dropbox', 'box', 'googledrive')
  | where isnotempty(SrcFileName)
  | project DetectionTime, DstUserName, SrcFileName, EventOriginalResultDetails, SecurityRiskName, VirusName
  | extend FileCustomEntity = SrcFileName, AccountCustomEntity = DstUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

