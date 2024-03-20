---
id: d8dd00ec-3bec-11ec-8d3d-0242ac130003
name: NGINX - Top URLs client errors
description: |
  'Query shows URLs list with client errors.'
severity: Medium
requiredDataConnectors:
  - connectorId: NGINXHTTPServer
    dataTypes:
      - NGINXHTTPServer
tactics:
  - Impact
  - InitialAccess
relevantTechniques:
  - T1498
  - T1190
  - T1133
query: "```kusto\nNGINXHTTPServer\n| where TimeGenerated > ago(24h)\n| where HttpStatusCode >= 400 and HttpStatusCode <= 499\n| summarize TopUrls = count() by (tostring(UrlOriginal))\n| top 20 by TopUrls desc \n| extend UrlCustomEntity = UrlOriginal\n```"
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

