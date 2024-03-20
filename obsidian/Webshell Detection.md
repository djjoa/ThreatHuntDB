---
id: cc087e7c-4db0-4bf9-9e48-287a9c9c3fbc
name: Webshell Detection
description: |
  Web shells are scripts that allow remote administration when uploaded to a web server. This query can detect web shells using GET requests by searching for keywords in URL strings.
description-detailed: "'Web shells are script that when uploaded to a web server can be used for remote administration. \nAttackers often use web shells to obtain unauthorized access, escalate //privilege as well as further compromise the environment. \nThe query detects web shells that use GET requests by keyword searches in URL strings. \nThis is based out of sigma rules described. \nThere could be some web sites like wikis with articles on os commands and pages that include the os //commands in the URLs that might cause FP.'\n"
requiredDataConnectors:
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1505
query: "```kusto\n\nlet command = \"(?i)net(1)?(.exe)?(%20){1,}user|cmd(.exe)?(%20){1,}/c(%20){1,}\";\nW3CIISLog\n| where csMethod == \"GET\" \n| where ( csUriQuery has \"whoami\" or csUriQuery matches regex command ) or \n        ( csUriStem has \"whoami\" or csUriStem matches regex command ) or\n        ( csReferer has \"whoami\" or csReferer matches regex command )\n| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated), ConnectionCount = count() \nby Computer, sSiteName, sIP, cIP, csUserName, csUriQuery, csMethod, scStatus, scSubStatus, scWin32Status\n| extend timestamp = StartTime, IPCustomEntity = cIP, HostCustomEntity = Computer, AccountCustomEntity = csUserName \n```"
version: 1.0.0
---

