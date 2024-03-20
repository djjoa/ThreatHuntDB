---
id: 8bb86556-67b4-11ec-90d6-0242ac120003
name: ApexOne - Top sources with alerts
description: |
  'Query shows list of top sources with alerts.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - Execution
  - InitialAccess
  - PrivilegeEscalation
  - DefenseEvasion
  - CommandAndControl
  - Exfiltration
relevantTechniques:
  - T1204
  - T1189
  - T1068
  - T1202
  - T1112
  - T1055
  - T1071
  - T1095
  - T1537
  - T1567
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where isnotempty(SrcIpAddr)\n| summarize IpCount = count() by SrcIpAddr\n| top 20 by IpCount desc \n| extend IPCustomEntity = SrcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

