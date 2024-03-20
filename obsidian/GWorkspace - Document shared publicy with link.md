---
id: c7c65c78-5dab-11ec-bf63-0242ac130002
name: GWorkspace - Document shared publicy with link
description: |
  'Query searches document shared publicy with link.'
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
query: "```kusto\nGWorkspaceActivityReports \n| where TimeGenerated > ago(24h)\n| where EventType =~ 'acl_change'\n| where Visibility =~ 'people_with_link'\n| extend AccountCustomEntity = ActorEmail\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

