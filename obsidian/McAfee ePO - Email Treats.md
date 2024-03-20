---
id: 851b63f1-cc5d-44d5-b505-9444a5e87076
name: McAfee ePO - Email Treats
description: |
  'Query searches for email related threat events.'
requiredDataConnectors:
  - connectorId: McAfeeePO
    dataTypes:
      - Syslog
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: "```kusto\nlet lbtime = 24h;\nMcAfeeEPOEvent\n| where TimeGenerated > ago(lbtime)\n| where EventId in ('1417', '1418', '1419', '1420', '1500', '1501', '1502', '1503', '1504', '1505', '1506', '1507', '1513', '1514')\n| extend EventMessage = case(EventId == '1417', \"Email message deleted (user defined detection)\",\n  EventId == '1418', \"Email message deleted (user defined detection), Clean failed\",\n  EventId == '1419', \n  \"Email message deleted (user defined detection), Move failed\",\n  EventId == '1420', \"Email message deleted (user defined detection), Delete failed\",\n  EventId == '1500', \"Infected email cleaned (Medium)\",\n  EventId == '1501', \"Infected email quarantined\",\n  EventId == '1502', \"Unable to clean infected mail\", \n  EventId == '1503', \"Infected email detected\",\n  EventId == '1504', \"Infected mail item deleted\",\n  EventId == '1505', \"Email content filtered\",\n  EventId == '1506', \"Email content blocked\",\n  EventId == '1507', \"Inbound email suspended for low disk\",\n  EventId == '1513', \"Mail virus quarantined and cleaned\",\n  \"Mail virus quarantined (not cleaned)\")\n| project DvcIpAddr, EventId, EventMessage\n| extend IPCustomEntity = DvcIpAddr```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

