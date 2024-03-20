---
id: dff3c841-6e3e-432e-ad68-3ddd7326bc01
name: McAfee ePO - Agent Errors
description: |
  'Query searches for error events from McAfee agents.'
requiredDataConnectors:
  - connectorId: McAfeeePO
    dataTypes:
      - Syslog
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1070
query: "```kusto\nlet lbtime = 24h;\nMcAfeeEPOEvent\n| where TimeGenerated > ago(lbtime)\n| where EventId in ('2402', '2412', '1119', '1123', '2201', '2202', '2204', '2208', '3020', '3021')\n| extend EventMessage = case(EventId == '2402', \"Update Failed\",\n                              EventId == '2412', \"Deployment Failed\",\n                              EventId == '1119', \n                              \"The update failed; see event log\",\n                              EventId == '1123', \"The upgrade failed; see event log\",\n                              EventId == '2201', \"McAfee Agent: Failed to install software package\",\n                              EventId == '2202', \"McAfee Agent: Install retry limit reached for software package\",\n                              EventId == '2204', \"McAfee Agent: Insufficient disk space to install software\", \n                              EventId == '2208', \"McAfee Agent: Insufficient disk space to download software\",\n                              EventId == '3020', \"Invalid virus signature files\",\n                              \"Scan engine error\")\n| project DvcIpAddr, EventId, EventMessage\n| extend IPCustomEntity = DvcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

