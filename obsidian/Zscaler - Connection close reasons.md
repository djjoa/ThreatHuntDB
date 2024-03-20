---
id: 5467efc0-422c-11ec-81d3-0242ac130003
name: Zscaler - Connection close reasons
description: |
  'Query shows connection close reasons.'
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
query: "```kusto\nlet User_set = \nZPAEvent\n| where DvcAction has \"close\"\n| summarize Users = make_set(DstUserName)by EventResult;\nZPAEvent\n| where DvcAction has \"close\"\n| summarize EventCount = count()by EventResult\n| join (User_set) on EventResult\n| project-away EventResult1\n| top 20 by EventCount desc \n| extend AccountCustomEntity = Users\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

