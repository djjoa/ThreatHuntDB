---
id: 1f99e54f-0e75-474e-8232-90963207f02b
name: Imperva - Non HTTP/HTTPs applications
description: |
  'Query searches for non HTTP/HTTPs applications.'
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
  | where NetworkApplicationProtocol !in~ ('HTTP', 'HTTPs')
  | summarize count() by DstIpAddr, NetworkApplicationProtocol
  | extend IPCustomEntity = DstIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

