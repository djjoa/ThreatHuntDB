---
id: 8c35faed-a8cf-4d8d-8c67-f14f2ff6e7e9
name: Cisco WSA - Potentially risky resources
description: |
  'Query searches for potentially risky resources.'
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
  | where DvcAction =~ 'BLOCK_CONTINUE_WEBCAT'
  | project UrlOriginal, SrcUserName, SrcIpAddr
  | extend URLCustomEntity = UrlOriginal, AccountCustomEntity = SrcUserName, IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: URLCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---
