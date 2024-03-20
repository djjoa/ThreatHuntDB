---
id: baf67720-4623-11ec-81d3-0242ac130003
name: Zscaler - Top source IP
description: |
  'Query shows top source IP.'
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
query: "```kusto\nZPAEvent\n| where DvcAction == 'open'\n| summarize EventCount = count()by SrcIpAddr\n| top 20 by EventCount desc \n| extend IPCustomEntity = SrcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

