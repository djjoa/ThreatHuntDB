---
id: 0caa3472-67b6-11ec-90d6-0242ac120003
name: ApexOne - Behavior monitoring operations by users
description: |
  'Shows behavior monitoring operations by users.'
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
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Behavior Monitoring\"\n| extend DeviceCustomNumber3 = coalesce(\n                                  column_ifexists(\"FieldDeviceCustomNumber3\", long(null)),\n                                  DeviceCustomNumber3,\n                                  long(null)\n                              )\n| where isnotempty(DeviceCustomNumber3)\n| extend Translatedoperation = case(\nDeviceCustomNumber3 == \"101\", \"Create Process\", \nDeviceCustomNumber3 == \"102\", \"Open\",\nDeviceCustomNumber3 == \"103\", \"Terminate\",\nDeviceCustomNumber3 == \"104\", \"Terminate\", \nDeviceCustomNumber3 == \"301\", \"Delete\",\nDeviceCustomNumber3 == \"302\", \"Write\",\nDeviceCustomNumber3 == \"303\", \"Access\", \nDeviceCustomNumber3 == \"401\", \"Create File\",\nDeviceCustomNumber3 == \"402\", \"Close\",\nDeviceCustomNumber3 == \"403\", \"Execute\", \nDeviceCustomNumber3 == \"501\", \"Invoke\",\nDeviceCustomNumber3 == \"601\", \"Exploit\",\nDeviceCustomNumber3 == \"9999\", \"Unhandled Operation\",\n\"unknown\")\n| summarize OperationCount = count() by Translatedoperation, DstUserName\n| sort by OperationCount desc \n| extend AccountCustomEntity = DstUserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

