---
id: 49d88918-03c8-4e22-9c8b-843e79cad6f5
name: Google DNS - Rare domains
description: |
  'Query searches for requests rare domains.'
severity: Medium
requiredDataConnectors:
  - connectorId: GCPDNSDataConnector
    dataTypes:
      - GCPCloudDNS
tactics:
  - CommandAndControl
relevantTechniques:
  - T1095
query: |-
  ```kusto
  GCPCloudDNS
  | where TimeGenerated > ago(24h)
  | summarize count() by Query
  | order by count_ asc
  | top 10 by count_
  | extend DNSCustomEntity = Query
  ```
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: DNSCustomEntity
---

