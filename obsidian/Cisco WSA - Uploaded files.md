---
id: 9d08418d-e21e-4fd6-b9bc-d80ce786d2da
name: Cisco WSA - Uploaded files
description: |
  'Query searches for uploaded files.'
severity: Medium
requiredDataConnectors:
  - connectorId: CiscoWSA
    dataTypes:
      - CiscoWSAEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1189
query: |-
  ```kusto
  CiscoWSAEvent
  | where TimeGenerated > ago(24h)
  | where HttpRequestMethod in~ ('POST', 'PUT')
  | where isnotempty(AmpFileName)
  | project AmpFileName, SrcUserName
  | extend AccountCustomEntity = SrcUserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---
