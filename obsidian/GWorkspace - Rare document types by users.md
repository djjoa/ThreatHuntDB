---
id: 0b20d206-5dab-11ec-bf63-0242ac130002
name: GWorkspace - Rare document types by users
description: |
  'Query searches rare document types by users.'
severity: Medium
requiredDataConnectors:
  - connectorId: GoogleWorkspaceReportsAPI
    dataTypes:
      - GWorkspaceActivityReports
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: "```kusto\nGWorkspaceActivityReports\n| where TimeGenerated > ago(24h)\n| where isnotempty(DocType)\n| summarize users = make_set(ActorEmail), count() by DocType\n| top 20 by count_ asc \n| extend AccountCustomEntity = users\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

