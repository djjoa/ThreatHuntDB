---
id: 3de523b5-9608-43d5-801e-732c741dd82e
name: Rare User Agent strings
description: |
  'This will check for Rare User Agent strings over the last 3 days.  This can indicate potential probing of your IIS servers.'
severity: Low
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
query: "```kusto\n\nW3CIISLog\n//Exclude local addresses, using ipv4_is_private operator\n|where ipv4_is_private(cIP) == false and  cIP !startswith \"fe80\" and cIP !startswith \"::\" and cIP !startswith \"127.\"  \n| where isnotempty(csUserAgent) and csUserAgent !in~ (\"-\", \"MSRPC\")\n| extend csUserAgent_size = string_size(csUserAgent)\n| project TimeGenerated, sSiteName, sPort, csUserAgent, csUserAgent_size, csUserName , csMethod, csUriStem, sIP, cIP, scStatus, \nscSubStatus, scWin32Status, csHost \n| join (\n    W3CIISLog\n\t  // The below line can be used to exclude local IPs if these create noise\n    |where ipv4_is_private(cIP) == false and  cIP !startswith \"fe80\" and cIP !startswith \"::\" and cIP !startswith \"127.\"  \n    | where isnotempty(csUserAgent) and csUserAgent !in~ (\"-\", \"MSRPC\") \n    | extend csUserAgent_size = string_size(csUserAgent)\n    | summarize csUserAgent_count = count() by bin(csUserAgent_size, 1)\n    | top 20 by csUserAgent_count asc nulls last \n) on csUserAgent_size\n| project TimeGenerated, sSiteName, sPort, sIP, cIP, csUserAgent, csUserAgent_size, csUserAgent_count, csUserName , csMethod, csUriStem, \nscStatus, scSubStatus, scWin32Status, csHost\n| extend timestamp = TimeGenerated, IPCustomEntity = cIP, HostCustomEntity = csHost, AccountCustomEntity = csUserName \n```"
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

