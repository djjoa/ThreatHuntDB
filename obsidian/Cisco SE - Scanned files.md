---
id: 1eae0963-16be-4d49-9491-6fc54f8254fd
name: Cisco SE - Scanned files
description: |
  'Query searches for scanned files.'
severity: Medium
requiredDataConnectors:
  - connectorId: CiscoSecureEndpoint
    dataTypes:
      - CiscoSecureEndpoint
tactics:
  - Execution
relevantTechniques:
  - T1204.002
query: |-
  ```kusto
  CiscoSecureEndpoint
  | where TimeGenerated > ago(24h)
  | where EventMessage =~ 'Scan Started'
  | order by TimeGenerated desc
  | extend FileCustomEntity = SrcFileName
  ```
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

