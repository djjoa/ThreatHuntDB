---
id: 934f19a5-f4bc-47eb-a213-db918b097434
name: Imperva - Top applications with error requests
description: |
  'Query searches for top applications with protocol or network errors.'
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
  | where DvcAction startswith 'REQ_BAD_'
  | summarize count() by DstIpAddr, DstDomainHostname
  | top 10 by count_
  | extend IPCustomEntity = DstIpAddr, DomainNameCustom = DstDomainHostname
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: CustomDomainName
---

