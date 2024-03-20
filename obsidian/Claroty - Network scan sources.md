---
id: 6c43a50e-2e59-48d9-848b-825f50927bbf
name: Claroty - Network scan sources
description: |
  'Query searches for sources of network scans.'
severity: Medium
requiredDataConnectors:
  - connectorId: Claroty
    dataTypes:
      - ClarotyEvent
  - connectorId: ClarotyAma
    dataTypes:
      - ClarotyEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: |-
  ```kusto
  ClarotyEvent
  | where TimeGenerated > ago(24h)
  | where EventOriginalType has_any ('Network Scan', 'TCP Scan', 'UDP Scan') or EventType has_any ('Network Scan', 'TCP Scan', 'UDP Scan')
  | project TimeGenerated, SrcIpAddr
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---
