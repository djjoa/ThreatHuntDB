---
id: 5fc73535-738c-46ce-88a2-69bda3fada02
name: Bitglass - Insecure web protocol
description: |
  'Query searches for usage of http protocol.'
severity: Medium
requiredDataConnectors:
  - connectorId: Bitglass
    dataTypes:
      - Bitglass
tactics:
  - Exfiltration
relevantTechniques:
  - T1567
query: |-
  ```kusto
  Bitglass
  | where TimeGenerated > ago(24h)
  | where EventType in~ ('swgweb', 'swgwebdlp')
  | where NetworkProtocol =~ 'http'
  | extend AccountCustomEntity = User, IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

