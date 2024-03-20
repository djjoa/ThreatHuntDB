---
id: a52d874d-dc45-438f-b395-92d1a3ebcf76
name: Ping Federate - New users
description: |
  'Query searches for new users.'
severity: Low
requiredDataConnectors:
  - connectorId: PingFederate
    dataTypes:
      - PingFederateEvent
  - connectorId: PingFederateAma
    dataTypes:
      - PingFederateEvent
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\nlet known_users = \nPingFederateEvent\n| where TimeGenerated between (ago(30d) .. (1d))\n| where isnotempty(DstUserName)\n| summarize makeset(DstUserName);\nPingFederateEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(DstUserName)\n| where DstUserName !in (known_users)\n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

