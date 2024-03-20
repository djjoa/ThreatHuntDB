---
id: 975419eb-7041-419c-b8f0-c4bf513cf2b2
name: Cisco Umbrella - High values of Uploaded Data
description: |
  'A normal user activity consists mostly of downloading data. Uploaded data is usually small unless there is a file/data upload to a website. Calculate the sum of BytesOut per Source-Destination pair over 12/24 hours.'
requiredDataConnectors: []
tactics:
  - Exfiltration
relevantTechniques:
  - T1020
query: "```kusto\nlet timeframe = 1d;\nCisco_Umbrella \n| where EventType == \"proxylogs\"\n| where TimeGenerated > ago(timeframe)\n| summarize sum(SrcBytes) by SrcIpAddr,DstIpAddr\n| sort by sum_SrcBytes desc\n| project SrcIpAddr, DstIpAddr\n| extend IpCustomEntity = SrcIpAddr\n```"
---

