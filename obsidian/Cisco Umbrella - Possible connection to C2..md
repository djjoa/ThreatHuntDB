---
id: 85421f18-2de4-42ff-9ef4-058924dcb1bf
name: Cisco Umbrella - Possible connection to C2.
description: |
  'Calculate the count of BytesIn per Source-Destination pair over 12/24 hours. Higher values may indicate beaconing. C2 servers reply with the same data, making BytesIn value the same.'
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071
query: "```kusto\nlet timeframe = 1d;\nCisco_Umbrella \n| where EventType == \"proxylogs\"\n| where TimeGenerated > ago(timeframe)\n| summarize count() by SrcIpAddr, DstIpAddr, SrcBytes\n| sort by count_ desc\n| extend Message = \"Possible communication with C2\"\n| extend IPCustomEntity = SrcIpAddr\n```"
---

