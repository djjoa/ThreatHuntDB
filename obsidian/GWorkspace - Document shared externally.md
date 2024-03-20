---
id: 00d743e2-5dac-11ec-bf63-0242ac130002
name: GWorkspace - Document shared externally
description: |
  'Query searches document shared externally.'
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - Exfiltration
  - Impact
relevantTechniques:
  - T1048
  - T1565
query: "```kusto\nGWorkspaceActivityReports \n| where TimeGenerated > ago(24h)\n| where EventType =~ 'acl_change'\n| where Visibility =~ 'shared_externally'\n| extend AccountCustomEntity = ActorEmail\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

