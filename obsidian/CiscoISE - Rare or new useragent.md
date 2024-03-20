---
id: 32abe28a-c1c8-4eb4-adfb-858abdbacbfe
name: CiscoISE - Rare or new useragent
description: |
  'Search for rare useragent values.'
requiredDataConnectors:
  - connectorId: CiscoISE
    dataTypes:
      - Syslog
tactics:
  - InitialAccess
query: "```kusto\nlet dt_lookBackPeriod = 30d;\nlet dt_lookBackTime = 24h;\nlet knownUserAgents =\nCiscoISEEvent \n| where TimeGenerated between (ago(dt_lookBackPeriod) .. ago(dt_lookBackTime))\n| where HttpUserAgentOriginal != ''\n| summarize makelist(HttpUserAgentOriginal)\n;\nCiscoISEEvent\n| where TimeGenerated > ago(dt_lookBackTime)\n| where HttpUserAgentOriginal !in (knownUserAgents)\n| summarize EventCount = count() by HttpUserAgentOriginal\n| project-away EventCount\n```"
---

