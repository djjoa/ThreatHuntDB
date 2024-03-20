---
id: 433ccdb0-67b6-11ec-90d6-0242ac120003
name: ApexOne - Behavior monitoring event types by users
description: |
  'Shows behavior monitoring event types.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - Privilege Escalation
  - Persistence
relevantTechniques:
  - T1546
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Behavior Monitoring\"\n| where isnotempty(Event_Type)\n| extend TypeOfEvent= case(\nEvent_Type == \"1\", \"Process\",\nEvent_Type == \"2\", \"Process image\",\nEvent_Type == \"4\", \"Registry\",\nEvent_Type == \"8\", \"File system\",\nEvent_Type == \"16\", \"Driver\",\nEvent_Type == \"32\", \"SDT\", \nEvent_Type == \"64\", \"System API\",\nEvent_Type == \"128\", \"User Mode\",\nEvent_Type == \"2048\", \"Exploit\",\nEvent_Type == \"65535\", \"All\",\n\"unknown\")\n| summarize EventTypeCount = count() by TypeOfEvent, DstUserName\n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

