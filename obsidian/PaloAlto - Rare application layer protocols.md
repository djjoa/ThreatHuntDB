---
id: 0a18756a-5123-11ec-bf63-0242ac130002
name: PaloAlto - Rare application layer protocols
description: |
  'Query shows Rare application layer protocols'
severity: Low
requiredDataConnectors:
  - connectorId: PaloAltoCDL
    dataTypes:
      - PaloAltoCDLEvent
  - connectorId: PaloAltoCDLAma
    dataTypes:
      - PaloAltoCDLEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: "```kusto\nPaloAltoCDLEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(NetworkApplicationProtocol) \n| summarize ApplicationLayerProtocol = count() by NetworkApplicationProtocol\n| top 10 by ApplicationLayerProtocol asc\n| extend UrlCustomEntity = NetworkApplicationProtocol\n```"
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: UrlCustomEntity
---

