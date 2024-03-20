---
id: 191bd49e-4881-11ec-81d3-0242ac130003
name: Tomcat - Top files with error requests
description: |
  'Query shows list of files with error requests.'
severity: Medium
requiredDataConnectors:
  - connectorId: ApacheTomcat
    dataTypes:
      - TomcatEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nTomcatEvent\n| where TimeGenerated > ago(24h)\n| where HttpStatusCode >= 400 and HttpStatusCode <= 599 \n| extend File = extract(@\"(.*\\/)?(.*)\", 2, tostring(UrlOriginal))\n| where isnotempty(File)\n| summarize TotalFile = count() by File\n| top 20 by TotalFile desc\n| extend FileCustomEntity = File\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

