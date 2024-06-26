---
id: 4a8a88af-4f40-40bd-aca8-e016dd6960de
name: Imperva - Rare client applications
description: |
  'Query searches for rare client applications used.'
severity: Medium
requiredDataConnectors:
  - connectorId: ImpervaWAFCloudAPI
    dataTypes:
      - ImpervaWAFCloud
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: |-
  ```kusto
  ImpervaWAFCloud
  | where TimeGenerated > ago(24h)
  | where isnotempty(ClientApp)
  | summarize count() by ClientApp
  | top 10 by count_ asc
  | extend AppCustomEntity = ClientApp
  ```
entityMappings:
  - entityType: CloudApplication
    fieldMappings:
      - identifier: Name
        columnName: AppCustomEntity
---

