---
id: 22545900-422d-11ec-81d3-0242ac130003
name: Zscaler - Server error by user
description: |
  'Query shows server error by user.'
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
query: "```kusto\nZPAEvent\n| where EventResult has \"AST_MT_SETUP_ERR_OPEN_SERVER_ERROR\"\n| summarize ips = count()by DstUserName\n| top 20 by ips desc \n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

