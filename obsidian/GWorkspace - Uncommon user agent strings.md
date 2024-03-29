---
id: 1efb71b6-5da9-11ec-bf63-0242ac130002
name: GWorkspace - Uncommon user agent strings
description: |
  'Query searches uncommon user agent strings.'
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - Persistence
  - Collection
relevantTechniques:
  - T1185
  - T1176
query: |-
  ```kusto
  let length = 10;
  GWorkspaceActivityReports
  | where TimeGenerated > ago(24h)
  | where isnotempty(UserAgentOriginal)
  | where strlen(UserAgentOriginal) < length
  | extend UrlCustomEntity = UserAgentOriginal, AccountCustomEntity = ActorEmail
  ```
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

