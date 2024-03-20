---
id: a787a819-40df-4c9f-a5ae-850d5a2a0cf6
name: URI requests from single client
description: |
  'This finds connections to server files requested by only one client. Effective when actor uses static operational IP addresses. Threshold can be modified. Larger execution window increases reliability of results.'
description_detailed: "'This will look for connections to files on the server that are requested by only a single client. \nThis analytic will be effective where an actor is utilising relatively static operational IP addresses. The threshold can be modified. \nThe larger the execution window for this query the more reliable the results returned.'\n"
severity: Low
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: "```kusto\n\n\nlet clientThreshold = 1;\nlet scriptExtensions = dynamic([\".php\", \".aspx\", \".asp\", \".cfml\"]);\nlet data = W3CIISLog\n| where csUriStem has_any(scriptExtensions)\n// find sucessfull connection \n|where scStatus == 200\n//Exclude local addresses, needs editing to match your network configuration using ipv4_is_private operator\n|where ipv4_is_private(cIP) == false and  cIP !startswith \"fe80\" and cIP !startswith \"::\" and cIP !startswith \"127.\"\n// excluded internal web page \n|where ipv4_is_private(sIP) == false   \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), makelist(cIP), dcount(TimeGenerated) by csUriStem, sSiteName, csUserAgent;\ndata\n| mvexpand list_cIP\n| distinct StartTime, EndTime, tostring(list_cIP), csUriStem, sSiteName, csUserAgent\n| summarize StartTime = min(StartTime), EndTime = max(StartTime), dcount(list_cIP), makelist(list_cIP), makelist(sSiteName) by csUriStem, csUserAgent\n| where dcount_list_cIP == clientThreshold \n//Selects user agent strings that are probably browsers, comment out to see all\n| where csUserAgent startswith \"Mozilla\"\n| extend timestamp = StartTime, UserAgentCustomEntity = csUserAgent\n```"
entityMappings:
  - entityType: CloudLogonSession
    fieldMappings:
      - identifier: UserAgent
        columnName: csUserAgent
version: 1.0.2
metadata:
  source:
    kind: Community
  author:
    name: Thomas McElroy
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

