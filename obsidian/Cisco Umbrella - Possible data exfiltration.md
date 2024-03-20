---
id: 497d7250-87e1-49b1-a096-94f61c7ade9c
name: Cisco Umbrella - Possible data exfiltration
description: |
  'A normal user activity consists mostly of downloading data. Uploaded data is usually small unless there is a file/data upload to a website. Calculate the sum of BytesOut per Source-Destination pair over 12/24 hours.'
requiredDataConnectors: []
tactics:
  - Exfiltration
relevantTechniques:
  - T1020
query: "```kusto\nlet timeframe = 1d;\nCisco_Umbrella \n| where EventType == \"proxylogs\"\n| where TimeGenerated > ago(timeframe)\n| summarize sum(DstBytes) by SrcIpAddr,DstIpAddr\n| sort by sum_DstBytes desc\n| extend Message = \"Possible data exfiltration\"\n| extend IPCustomEntity = SrcIpAddr\n```"
---

