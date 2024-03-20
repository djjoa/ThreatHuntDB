---
id: ce9d58ce-51cd-11ec-bf63-0242ac130002
name: PaloAlto - Rare ports by user
description: |
  'Query shows rare ports by user.'
severity: Medium
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
query: "```kusto\nPaloAltoCDLEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(DstPortNumber) \n| summarize RarePorts = count() by DstPortNumber, DstIpAddr, DstUsername\n| top 20 by RarePorts asc \n| extend IPCustomEntity = DstIpAddr, AccountCustomEntity = DstUsername\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

