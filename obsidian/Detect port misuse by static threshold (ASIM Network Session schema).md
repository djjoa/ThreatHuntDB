---
id: 70e2a349-87f0-4266-809c-e92fc71e0830
name: Detect port misuse by static threshold (ASIM Network Session schema)
description: |
  'There is an normal amount of traffic that goes on a particular port in any organization. This hunting query identifies port usage higher than threshold defined in 'NetworkSession_Monitor_Configuration' watchlist to determine high port usage.'
tags:
  - Schema: ASimNetworkSessions
    SchemaVersion: 0.2.4
requiredDataConnectors:
  - connectorId: AWSS3
    dataTypes:
      - AWSVPCFlow
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
  - connectorId: Zscaler
    dataTypes:
      - CommonSecurityLog
  - connectorId: MicrosoftSysmonForLinux
    dataTypes:
      - Syslog
  - connectorId: PaloAltoNetworks
    dataTypes:
      - CommonSecurityLog
  - connectorId: AzureMonitor(VMInsights)
    dataTypes:
      - VMConnection
  - connectorId: AzureFirewall
    dataTypes:
      - AzureDiagnostics
  - connectorId: AzureNSG
    dataTypes:
      - AzureDiagnostics
  - connectorId: CiscoASA
    dataTypes:
      - CommonSecurityLog
  - connectorId: Corelight
    dataTypes:
      - Corelight_CL
  - connectorId: AIVectraStream
    dataTypes:
      - VectraStream
  - connectorId: CheckPoint
    dataTypes:
      - CommonSecurityLog
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
  - connectorId: CiscoMeraki
    dataTypes:
      - Syslog
      - CiscoMerakiNativePoller
tactics:
  - CommandAndControl
  - InitialAccess
  - Execution
relevantTechniques:
  - T1905
  - T1190
  - T1059
  - T1203
query: "```kusto\nlet lookback = 10m; \nlet mapping = _GetWatchlist('NetworkSession_Monitor_Configuration')\n| where Type == \"Hunting\" and ThresholdType == \"Static\" and Severity != \"Disabled\"  \n| extend Ports = split(Ports,\",\"),\n        App = split(App,\",\"),\n        Protocol = split(Protocol,\",\"),\n        Direction = split(Direction,\",\"),\n        Action = split(Action,\",\")\n| project Ports, App, Protocol, Direction, Action, Type, ThresholdType, Threshold, Severity, Tactic, Name, Description\n| mv-expand Ports\n| mv-expand App\n| mv-expand Protocol\n| mv-expand Direction\n| mv-expand Action\n| extend Ports = tostring(Ports), App = tostring(App), Protocol = tostring(Protocol), Direction = tostring(Direction), Action = tostring(Action), Threshold = toint(Threshold)\n;\nlet nosummary = materialize(\n              union isfuzzy=true \n                (\n                    NetworkCustomAnalytics_protocol_CL \n                    | project v = int(2)\n                ),\n                (\n                    print int(1) \n                    | project v = print_0\n                )\n                | summarize maxv = max(v)\n                | extend nosum = (maxv > 1)\n              );\nlet allData = union isfuzzy=true \n    (\n        (datatable(exists:int, nosum:bool)[1,false] | join (nosummary) on nosum) | join (\n        _Im_NetworkSession(starttime=bin(now(-10m),10m), endtime=bin(now(),10m))\n        | where TimeGenerated > bin(now(-10m),10m)\n        | summarize Count=count() by NetworkProtocol, DstPortNumber, DstAppName, NetworkDirection, DvcAction, bin(TimeGenerated,10m)\n        | extend EventTime = TimeGenerated, Count = toint(Count), DstPortNumber = toint(DstPortNumber), exists=int(1)\n        ) on exists\n        | project-away exists, maxv, nosum*\n    ),\n    (\n        NetworkCustomAnalytics_protocol_CL\n        | where EventTime_t == toscalar(NetworkCustomAnalytics_protocol_CL | summarize max(EventTime_t))\n        | project-rename NetworkProtocol=NetworkProtocol_s, DstPortNumber=DstPortNumber_d, DstAppName=DstAppName_s, NetworkDirection=NetworkDirection_s, DvcAction=DvcAction_s, Count=count__d, EventTime=EventTime_t\n        | extend Count = toint(Count),DstPortNumber = toint(DstPortNumber)\n    )\n;\nallData\n      | where isnotempty(DstPortNumber)\n      | summarize Sum=sum(Count) by DstPortNumber, NetworkProtocol, NetworkDirection, DvcAction \n      | join kind=inner ['mapping'] where Ports has tostring(DstPortNumber)\n      | where Sum > Threshold         \n                and (Protocol == \"*\" or Protocol has NetworkProtocol)\n                and (Direction == \"*\" or Direction has NetworkDirection)\n                and (Action == \"*\" or Action has DvcAction)\n      | project Name, Description, NetworkProtocol, DstPortNumber, NetworkDirection, DvcAction, Severity, Tactic\n      | summarize NetworkProtocols=make_set_if(NetworkProtocol,isnotempty(NetworkProtocol),20), \n                  NetworkDirections=make_set_if(NetworkDirection,isnotempty(NetworkDirection),5), \n                  DvcActions=make_set_if(DvcAction,isnotempty(DvcAction),10) by Name, Severity, Tactic, DstPortNumber, Description\n```"
---

