---
id: afe13b7c-38b8-11ec-8d3d-0242ac130003
name: Apache - Top files requested with errors
description: |
  'Query shows list of files with error requests.'
severity: Medium
requiredDataConnectors:
  - connectorId: ApacheHTTPServer
    dataTypes:
      - ApacheHTTPServer
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nApacheHTTPServer\n| where TimeGenerated > ago(24h)\n| where HttpStatusCode >= 400 and HttpStatusCode <= 599 \n| extend File = extract(@\"(.*\\/)?(.*)\", 2, tostring(UrlOriginal))\n| where isnotempty(File)\n| summarize TotalFile = count() by File\n| top 20 by TotalFile desc\n| extend FileCustomEntity = File\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

