---
id: 55393e5b-3f7e-4d40-85e5-38ef9ecd8484
name: Cisco Umbrella - Higher values of count of the Same BytesIn size
description: |
  'Calculate the count of BytesIn per Source-Destination pair over 24 hours. Higher values may indicate beaconing.'
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071
query: "```kusto\nlet timeframe = 1d;\nCisco_Umbrella \n| where EventType == \"proxylogs\"\n| where TimeGenerated > ago(timeframe)\n| summarize count() by SrcIpAddr,DstIpAddr, SrcBytes\n| sort by count_ desc\n| extend Message = \"Possible communication with C2\"\n| project Message, SrcIpAddr, DstIpAddr\n| extend IpCustomEntity = SrcIpAddr\n```"
---

