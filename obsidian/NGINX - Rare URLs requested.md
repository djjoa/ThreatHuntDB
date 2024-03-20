---
id: fd2ae5f6-3bea-11ec-8d3d-0242ac130003
name: NGINX - Rare URLs requested
description: |
  'Query shows rare URLs requested.'
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
query: "```kusto\nNGINXHTTPServer\n| where TimeGenerated > ago(24h)\n| summarize count() by tostring(UrlOriginal)\n| top 20 by count_ asc \n| extend UrlCustomEntity = UrlOriginal\n```"
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

