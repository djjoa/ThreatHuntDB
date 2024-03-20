---
id: 0bce5bd0-cc19-43de-a5ab-47dbc5c6c600
name: Ping Federate - Authentication from unusual sources
description: |
  'Query searches for unusual sources of authentication.'
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
query: "```kusto\nlet known_src = \nPingFederateEvent\n| where TimeGenerated between (ago(30d) .. (1d))\n| where isnotempty(SrcIpAddr)\n| summarize makeset(SrcIpAddr);\nPingFederateEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(SrcIpAddr)\n| where SrcIpAddr !in (known_src)\n| extend IpCustomEntity = SrcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpCustomEntity
---

