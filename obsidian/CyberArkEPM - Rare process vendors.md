---
id: 37031fed-f7cb-45fc-a1c2-e2eab46cbba2
name: CyberArkEPM - Rare process vendors
description: |
  'Query shows rare process vendors.'
severity: Low
requiredDataConnectors:
  - connectorId: CyberArkEPM
    dataTypes:
      - CyberArkEPM
tactics:
  - Execution
relevantTechniques:
  - T1204
query: |-
  ```kusto
  CyberArkEPM
  | where TimeGenerated > ago(24h)
  | where isnotempty(ActingProcessFileCompany)
  | summarize count() by ActingProcessFileCompany, ActingProcessFileInternalName
  | top 25 by count_ asc
  | extend ProcCustomEntity = ActingProcessFileCompany
  ```
entityMappings:
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: ProcCustomEntity
---

