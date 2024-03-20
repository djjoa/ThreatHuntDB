---
id: d311eb1e-4231-11ec-81d3-0242ac130003
name: Zscaler - Rare urlhostname requests
description: |
  'Query shows rare urlhostname requests.'
severity: Low
requiredDataConnectors:
  - connectorId: ZscalerPrivateAccess
    dataTypes:
      - ZPAEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nZPAEvent\n| where isnotempty(UrlHostname)\n| summarize url = count()by UrlHostname\n| top 20 by url asc \n| extend UrlCustomEntity = UrlHostname\n```"
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

