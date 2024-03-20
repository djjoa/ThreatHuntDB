---
id: d2e6f31b-add1-4f44-b54d-1975a5605c1d
name: Web shell command alert enrichment
description: |
  'Extracts MDATP Alerts that indicate a command was executed by a web shell. Uses time window based querying to idneitfy the potential web shell location on the server, then enriches with Attacker IP and User Agent'
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
query: "```kusto\nlet scriptExtensions = dynamic([\".php\", \".jsp\", \".js\", \".aspx\", \".asmx\", \".asax\", \".cfm\", \".shtml\"]);\nlet lookupWindow = 1m;  \nlet lookupBin = lookupWindow / 2.0; \nlet distinctIpThreshold = 3; \nlet alerts = SecurityAlert  \n| extend alertData = parse_json(Entities), recordGuid = new_guid(); \nlet shellAlerts = alerts \n| where ProviderName =~ \"MDATP\"  \n| mvexpand alertData \n| where alertData.Type =~ \"file\" and alertData.Name =~ \"w3wp.exe\" \n| distinct SystemAlertId \n| join kind=inner (alerts) on SystemAlertId; \nlet alldata = shellAlerts  \n| mvexpand alertData \n| extend Type = alertData.Type; \nlet filedata = alldata  \n| extend id = tostring(alertData.$id)  \n| extend ImageName = alertData.Name  \n| where Type =~ \"file\" and ImageName != \"w3wp.exe\" \n| extend imagefileref = id;  \nlet commanddata = alldata  \n| extend CommandLine = tostring(alertData.CommandLine)  \n| extend creationtime = tostring(alertData.CreationTimeUtc)  \n| where Type =~ \"process\"  \n| where isnotempty(CommandLine)  \n| extend imagefileref = tostring(alertData.ImageFile.$ref); \nlet hostdata = alldata \n| where Type =~ \"host\" \n| project HostName = tostring(alertData.HostName), DnsDomain = tostring(alertData.DnsDomain), SystemAlertId \n| distinct HostName, DnsDomain, SystemAlertId; \nlet commandKeyedData = filedata \n| join kind=inner (  \ncommanddata  \n) on imagefileref \n| join kind=inner (hostdata) on SystemAlertId \n| project recordGuid, TimeGenerated, ImageName, CommandLine, TimeKey = bin(TimeGenerated, lookupBin), HostName, DnsDomain \n| extend Start = TimeGenerated; \nlet baseline = W3CIISLog  \n| project-rename SourceIP=cIP, PageAccessed=csUriStem \n| summarize dcount(SourceIP) by PageAccessed \n| where dcount_SourceIP <= distinctIpThreshold; \ncommandKeyedData \n| join kind=inner ( \nW3CIISLog   \n| where csUriStem has_any(scriptExtensions)  \n| extend splitUriStem = split(csUriStem, \"/\")  \n| extend FileName = splitUriStem[-1] | extend firstDir = splitUriStem[-2] | extend TimeKey = range(bin(TimeGenerated-lookupWindow, lookupBin), bin(TimeGenerated, lookupBin),lookupBin)  \n| mv-expand TimeKey to typeof(datetime)  \n| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by Site=sSiteName, HostName=sComputerName, AttackerIP=cIP, AttackerUserAgent=csUserAgent, csUriStem, filename=tostring(FileName), tostring(firstDir), TimeKey \n) on TimeKey, HostName \n| where (StartTime - EndTime) between (0min .. lookupWindow) \n| extend IPCustomEntity = AttackerIP, timestamp = StartTime\n| extend attackerP = pack(AttackerIP, AttackerUserAgent)  \n| summarize Site=make_set(Site), Attacker=make_bag(attackerP) by csUriStem, filename, tostring(ImageName), CommandLine, HostName, IPCustomEntity, timestamp\n| project Site, ShellLocation=csUriStem, ShellName=filename, ParentProcess=ImageName, CommandLine, Attacker, HostName, IPCustomEntity, timestamp\n| join kind=inner (baseline) on $left.ShellLocation == $right.PageAccessed\n```"
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

