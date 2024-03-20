---
id: 58ad26ee-3bed-11ec-8d3d-0242ac130003
name: NGINX - Top URLs server errors
description: |
  'Query shows URLs list with server errors.'
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
query: "```kusto\nNGINXHTTPServer\n| where TimeGenerated > ago(24h)\n| where HttpStatusCode >= 500 and HttpStatusCode <= 599\n| summarize TopUrls = count() by tostring(UrlOriginal)\n| top 20 by TopUrls desc \n| extend UrlCustomEntity = UrlOriginal\n```"
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

