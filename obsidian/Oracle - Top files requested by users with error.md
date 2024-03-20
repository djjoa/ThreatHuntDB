---
id: 34d32bf0-5741-11ec-bf63-0242ac130002
name: Oracle - Top files requested by users with error
description: |
  'Query shows list of files with error requests.'
severity: Medium
requiredDataConnectors:
  - connectorId: OracleWebLogicServer
    dataTypes:
      - OracleWebLogicServerEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nOracleWebLogicServerEvent\n| where TimeGenerated > ago(24h)\n| where HttpStatusCode >= 400 and HttpStatusCode <= 599 \n| extend File = extract(@\"(.*\\/)?(.*)\", 2, tostring(UrlOriginal))\n| where isnotempty(File)\n| summarize TotalFile = count() by File\n| top 20 by TotalFile desc\n| extend FileCustomEntity = File\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

