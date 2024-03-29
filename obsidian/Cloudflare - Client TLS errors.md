---
id: 20ef3865-fd1f-44a4-ac8f-8d026cf954e0
name: Cloudflare - Client TLS errors
description: |
  'Query searches for client TLS errors.'
severity: Medium
requiredDataConnectors:
  - connectorId: CloudflareDataConnector
    dataTypes:
      - Cloudflare
tactics:
  - InitialAccess
  - Impact
relevantTechniques:
  - T1190
  - T1133
  - T1498
query: |-
  ```kusto
  let err_tls = dynamic(['UNKNOWN', 'INTERNAL_ERROR', 'INVALID_CONFIG', 'INVALID_SNI', 'HANDSHAKE_FAILED']);
  Cloudflare
  | where TimeGenerated > ago(24h)
  | where ClientTlsStatus in~ (err_tls)
  | extend IPCustomEntity = SrcIpAddr
  | extend UrlCustomEntity = ClientRequestURI
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

