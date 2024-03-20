---
id: 3122423d-6c33-43c8-bc10-6d27b4350176
name: Exchange Server Suspicious URIs Visited
description: |
  'This query will detect paths suspicious associated with ProxyLogon exploitation, it will then calculate the percentage of suspicious URIs
  the user had visited in relation to the total number of URIs the user has visited. This query will assist in the detection of automated
  ProxyLogon exploitation.'
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
tags:
  - Exchange
query: "```kusto\n\n//Calculate number of suspicious URI stems visited by user\nW3CIISLog \n| where not(ipv4_is_private(cIP))\n| where (csUriStem matches regex @\"\\/owa\\/auth\\/[A-Za-z0-9]{1,30}\\.js\") or (csUriStem matches regex @\"\\/ecp\\/[A-Za-z0-9]{1,30}\\.(js|flt|css)\") or (csUriStem =~ \"/ews/exchange.asmx\")\n| extend userHash = hash_md5(strcat(cIP, csUserAgent))\n| summarize susCount=dcount(csUriStem), make_list(csUriStem), min(TimeGenerated), max(TimeGenerated) by userHash, cIP, csUserAgent\n| join kind=leftouter  (\n  //Calculate unique URI stems visited by each user\n  W3CIISLog\n  | where not(ipv4_is_private(cIP))\n  | extend userHash = hash_md5(strcat(cIP, csUserAgent))\n  | summarize allCount=dcount(csUriStem) by userHash\n) on userHash\n//Find instances where only a common endpoint was seen\n| extend containsDefault = iff(list_csUriStem contains \"/ews/exchange.asmx\", 1, 0)\n//If we only see the common endpoint and nothing else dump it\n| extend result = iff(containsDefault == 1, containsDefault+susCount, 0)\n| where result != 2\n| extend susPercentage = susCount / allCount * 100\n| where susPercentage > 90\n| project StartTime=min_TimeGenerated, EndTime=max_TimeGenerated, AttackerIP=cIP, AttackerUA=csUserAgent, URIsVisited=list_csUriStem, suspiciousPercentage=susPercentage, allUriCount=allCount, suspiciousUriCount=susCount\n| extend timestamp = StartTime, IPCustomEntity = AttackerIP\n```"
entityMappings:
  - entityType: NetworkConnection
    fieldMappings:
      - identifier: SourceAddress
        columnName: AttackerIP
---

