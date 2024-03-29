---
id: 4cf72a93-537a-4c1f-83a3-0a5b743fe93e
name: Imperva - Applications with insecure web protocol version
description: |
  'Query searches for with insecure web protocol version.'
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
  | where NetworkApplicationProtocoVersion !startswith 'TLSv1.2'
  | summarize count() by DstDomainHostname
  | extend DomainNameCustom = DstDomainHostname
  ```
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: CustomDomainName
---

