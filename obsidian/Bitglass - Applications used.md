---
id: 8702d847-e540-4a52-a419-6d617eb200ae
name: Bitglass - Applications used
description: |
  'Query searches for applications used.'
severity: Medium
requiredDataConnectors:
  - connectorId: Bitglass
    dataTypes:
      - Bitglass
tactics:
  - Exfiltration
relevantTechniques:
  - T1078
query: |-
  ```kusto
  Bitglass
  | where TimeGenerated > ago(24h)
  | where isnotempty(Application)
  | summarize count() by Application
  | extend AppCustomEntity = Application
  ```
entityMappings:
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: AppCustomEntity
---

