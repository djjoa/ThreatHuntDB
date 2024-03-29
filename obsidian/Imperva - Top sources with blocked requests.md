---
id: ec5b9eb6-f43a-40fc-ae65-2af9ae1e77ae
name: Imperva - Top sources with blocked requests
description: |
  'Query searches source IP addresses with blocked requests.'
severity: Medium
requiredDataConnectors:
  - connectorId: ImpervaWAFCloudAPI
    dataTypes:
      - ImpervaWAFCloud
tactics:
  - InitialAccess
  - Impact
relevantTechniques:
  - T1190
  - T1133
  - T1498
query: |-
  ```kusto
  ImpervaWAFCloud
  | where TimeGenerated > ago(24h)
  | where DvcAction startswith 'REQ_BLOCKED'
  | summarize count() by SrcIpAddr
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

