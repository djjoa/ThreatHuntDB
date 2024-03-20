---
id: d0a3cb7b-375e-402d-9827-adafe0ce386d
name: Web shell file alert enrichment
description: |
  'Extracts MDATP Alert for a web shell being placed on the server and then enriches this event with information from W3CIISLog to idnetigy the Attacker that placed the shell'
requiredDataConnectors:
  - connectorId: MicrosoftDefenderAdvancedThreatProtection
    dataTypes:
      - SecurityAlert
  - connectorId: AzureMonitor(IIS)
    dataTypes:
      - W3CIISLog
tactics:
  - PrivilegeEscalation
  - Persistence
query: "```kusto\nlet scriptExtensions = dynamic([\".php\", \".jsp\", \".js\", \".aspx\", \".asmx\", \".asax\", \".cfm\", \".shtml\"]);  \nSecurityAlert   \n| where ProviderName =~ \"MDATP\" \n| extend alertData = parse_json(Entities)  \n| mvexpand alertData  \n// Get only the file type from the JSON, this gives us the file name\n| where alertData.Type =~ \"file\"  \n// This can be expanded to include other script extensions \n| where alertData.Name has_any(scriptExtensions)\n| extend FileName = alertData.Name \n| project TimeGenerated, tostring(FileName), alertData.Directory \n| join (  \nW3CIISLog    \n| where csUriStem has_any(scriptExtensions) \n| extend splitUriStem = split(csUriStem, \"/\")  \n| extend FileName = splitUriStem[-1] \n| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by AttackerIP=cIP, AttackerUserAgent=csUserAgent, SiteName=sSiteName, ShellLocation=csUriStem, tostring(FileName)  \n) on FileName \n| project StartTime, EndTime, AttackerIP, AttackerUserAgent, SiteName, ShellLocation\n| extend timestamp = StartTime, IPCustomEntity = AttackerIP  \n```"
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Thomas McElroy
  support:
    tier: Community
  categories:
    domains: ["Security - Threat Protection"]
---

