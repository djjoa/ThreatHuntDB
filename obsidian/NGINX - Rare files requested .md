---
id: aaacb354-3bea-11ec-8d3d-0242ac130003
name: NGINX - Rare files requested
description: |
  'Query shows rare files requested'
severity: Medium
requiredDataConnectors:
  - connectorId: NGINXHTTPServer
    dataTypes:
      - NGINXHTTPServer
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nNGINXHTTPServer\n| where TimeGenerated > ago(24h)\n| extend File = extract(@\"(.*\\/)?(.*)\", 2, tostring(UrlOriginal))\n| where isnotempty(File)\n| summarize RareFiles = count() by File\n| top 20 by RareFiles asc \n| extend FileCustomEntity = File\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

