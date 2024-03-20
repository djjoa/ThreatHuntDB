---
id: 96451e96-67b5-11ec-90d6-0242ac120003
name: ApexOne - Behavior monitoring actions by files
description: |
  'Shows behavior monitoring actions taken for files.'
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
relevantTechniques:
  - T1204
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Behavior Monitoring\"\n| where isnotempty(DvcAction)\n| extend TranslatedAction = case(\nDvcAction == \"0\", \"Allow\", \nDvcAction == \"1\", \"Ask\",\nDvcAction == \"2\", \"Deny\",\nDvcAction == \"3\", \"Terminate\", \nDvcAction == \"4\", \"Read Only\",\nDvcAction == \"5\", \"Read/Write Only\",\nDvcAction == \"6\", \"Read/Execute Only\", \nDvcAction == \"7\", \"Feedback\",\nDvcAction == \"8\", \"Clean\",\nDvcAction == \"1002\", \"Unknown\", \nDvcAction == \"1003\", \"Assess\",\nDvcAction == \"1004\", \"Terminated. Files were recovered.\",\nDvcAction == \"1005\", \"Terminated. Some files were not recovered.\", \nDvcAction == \"1006\", \"Terminated. Files were not recovered.\",\nDvcAction == \"1007\", \"Terminated. Restart result: Files were recovered.\",\nDvcAction == \"1008\", \"Terminated: Restart result: Some files were not recovered.\", \nDvcAction == \"1009\", \"Terminated: Restart result: Riles were not recovered.\",\n\"unknown\")\n| summarize ActionByFiles = count() by TranslatedAction, FileName\n| top 20 by ActionByFiles asc\n| extend FileCustomEntity = FileName```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

