---
id: 26d5244a-462f-11ec-81d3-0242ac130003
name: Zscaler - Top connectors
description: |
  'Query shows top connectors.'
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
query: "```kusto\nZPAEvent\n| where isnotempty(Connector) \n| where Connector != 0\n| summarize summ = sum(tolong(BytesRxInterface))by Connector\n| top 20 by summ desc \n| extend ProcessCustomEntity = Connector\n```"
entityMappings:
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: ProcessCustomEntity
---

