---
id: bb6bf88e-5dab-11ec-bf63-0242ac130002
name: GWorkspace - Multi IP addresses by user
description: |
  'Query searches users with multi IP addresses.'
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto
  GWorkspaceActivityReports
  | where TimeGenerated > ago(24h)
  | where isnotempty(SrcIpAddr)
  | summarize UserIP = make_set(SrcIpAddr) by ActorEmail
  | where array_length(UserIP) > 3
  | extend IPCustomEntity = UserIP
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

