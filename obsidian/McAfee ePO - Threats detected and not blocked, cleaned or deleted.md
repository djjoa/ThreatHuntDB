---
id: 80c5904d-6a36-4b7c-82d4-180023a1f8b4
name: McAfee ePO - Threats detected and not blocked, cleaned or deleted
description: |
  'Query searches for events where threats were detected and not blocked, cleaned or deleted.'
requiredDataConnectors:
  - connectorId: McAfeeePO
    dataTypes:
      - Syslog
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1574
  - T1055
query: "```kusto\nlet lbtime = 24h;\nMcAfeeEPOEvent\n| where TimeGenerated > ago(lbtime)\n| where EventId in ('1095', '1096', '1099', '34937', '35102', '34938', '35106', '35111', '35117')\n| extend EventMessage = case(EventId == '1095', \"Access Protection rule violation detected and NOT blocked\",\n                              EventId == '1096', \"Port blocking rule violation detected and NOT blocked\",\n                              EventId == '1099', \n                              \"Buffer Overflow detected and NOT blocked\",\n                              EventId == '34937', \"Script security violation detected, AMSI would block\",\n                              EventId == '35102', \"Adaptive Threat Protection Would Block\",\n                              EventId == '34938', \"Script security violation detected, AMSI would delete\",\n                              EventId == '35106', \"Adaptive Threat Protection Would Clean\", \n                              EventId == '35111', \"Adaptive Threat Protection Would Contain\",\n                              \"Adaptive Threat Protection Would Block Source\")\n| project DvcIpAddr, EventId, EventMessage\n| extend IPCustomEntity = DvcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

