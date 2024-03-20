---
id: 378e53cd-c28a-46d7-8160-1920240bf09e
name: Ping Federate - Requests from unusual countries
description: |
  'Query searches for requests from unusual countries.'
severity: Medium
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
query: "```kusto\nlet known_geo = \nPingFederateEvent\n| where TimeGenerated between (ago(30d) .. (1d))\n| where isnotempty(DstGeoCountry)\n| summarize makeset(DstGeoCountry);\nPingFederateEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(DstGeoCountry)\n| where DstGeoCountry !in (known_geo)\n| extend IpCustomEntity = SrcIpAddr\n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

