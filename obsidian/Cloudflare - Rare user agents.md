---
id: a6f1938f-2f87-446c-83ac-624c277cfd32
name: Cloudflare - Rare user agents
description: |
  'Query searches rare user agent strings.'
severity: Low
requiredDataConnectors:
  - connectorId: CloudflareDataConnector
    dataTypes:
      - Cloudflare
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: |-
  ```kusto
  Cloudflare
  | where TimeGenerated > ago(24h)
  | where isnotempty(HttpUserAgentOriginal)
  | summarize count() by HttpUserAgentOriginal, SrcIpAddr
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

