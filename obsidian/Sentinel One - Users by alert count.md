---
id: 56500e23-4e64-45a5-a444-98a1acb2f700
name: Sentinel One - Users by alert count
description: |
  'Query shows users by alert count.'
severity: High
requiredDataConnectors:
  - connectorId: SentinelOne
    dataTypes:
      - SentinelOne
tactics:
  - InitialAccess
relevantTechniques:
  - T1204
query: "```kusto\nSentinelOne\n| where TimeGenerated > ago(24h)\n| where ActivityType == 3608\n| extend DstHostname = extract(@'detected on\\s(\\S+)\\.', 1, EventOriginalMessage)\n| join (SentinelOne \n      | where EventType =~ 'Agents.'\n      | where isnotempty(LastLoggedInUserName)\n      | project DstHostname=ComputerName, LastLoggedInUserName) on DstHostname\n| summarize count() by LastLoggedInUserName\n| extend AccountCustomEntity = LastLoggedInUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

