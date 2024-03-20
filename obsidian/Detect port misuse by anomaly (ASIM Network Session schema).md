---
id: 906c20c6-b62c-4af7-be91-d7300e3bded2
name: Detect port misuse by anomaly (ASIM Network Session schema)
description: |
  'This hunting query detect anomalous pattern in port usage with ASIM normalization. To tune the query to your environment configure it using the 'NetworkSession_Monitor_Configuration' watchlist.'
description-detailed: |
  'This hunting query detect anomalous pattern in port usage. The query utilize [ASIM](https://aka.ms/AboutASIM) normalization, and is applied to any source which supports the ASIM Network Session schema. To tune the query to your environment configure it using the 'NetworkSession_Monitor_Configuration' watchlist. Note that to enhance performance, the query uses summarized data generated from the summarization logic App.'
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
query: "```kusto\nlet lookback = 14d;\nlet mapping = _GetWatchlist('NetworkSession_Monitor_Configuration')\n| where Type == \"Hunting\" and ThresholdType == \"Anomaly\" and Severity != \"Disabled\"  \n| extend Ports = split(Ports,\",\"),\n        App = split(App,\",\"),\n        Protocol = split(Protocol,\",\"),\n        Direction = split(Direction,\",\"),\n        Action = split(Action,\",\")\n| project Ports, App, Protocol, Direction, Action, Type, ThresholdType, Threshold, Severity, Tactic, Name, Description\n| mv-expand Ports\n| mv-expand App\n| mv-expand Protocol\n| mv-expand Direction\n| mv-expand Action\n| extend Ports = tostring(Ports), App = tostring(App), Protocol = tostring(Protocol), Direction = tostring(Direction), Action = tostring(Action), Threshold = toint(Threshold)\n;\nlet AnomalyThreshold = 2.5;\nlet eps = materialize (_Im_NetworkSession | project TimeGenerated | where TimeGenerated > ago(5m) | count | extend Count = Count/300);\nlet maxSummarizedTime = toscalar (\n    union isfuzzy=true \n        (\n            NetworkCustomAnalytics_protocol_CL\n                | where EventTime_t > ago(lookback)\n                | summarize max_TimeGenerated=max(EventTime_t)\n                | extend max_TimeGenerated = datetime_add('minute',10,max_TimeGenerated)\n        ),\n        (\n            print(ago(lookback))\n            | project max_TimeGenerated = print_0\n        )\n      | summarize maxTimeGenerated = max(max_TimeGenerated) \n    );\nlet nosummary = materialize(\n              union isfuzzy=true \n                (\n                    NetworkCustomAnalytics_protocol_CL\n                    | where EventTime_t > ago(1d) \n                    | project v = int(2)\n                ),\n                (\n                    print int(1) \n                    | project v = print_0\n                )\n                | summarize maxv = max(v)\n                | extend nosum = (maxv > 1)\n              );\nlet allData = union isfuzzy=true \n    (\n        (datatable(exists:int, nosum:bool)[1,false] | where toscalar(eps) > 1000 | join (nosummary) on nosum) | join (\n        _Im_NetworkSession(starttime=todatetime(ago(2d)), endtime=now())\n        | where TimeGenerated > maxSummarizedTime\n        | summarize Count=count() by NetworkProtocol, DstPortNumber, DstAppName, NetworkDirection, DvcAction, bin(TimeGenerated,10m)\n        | extend EventTime = TimeGenerated, Count = toint(Count), DstPortNumber = toint(DstPortNumber), exists=int(1)\n        ) on exists\n        | project-away exists, maxv, nosum*\n    ),\n    (\n        (datatable(exists:int, nosum:bool)[1,false] | where toscalar(eps) between (501 .. 1000) | join (nosummary) on nosum) | join (\n        _Im_NetworkSession(starttime=todatetime(ago(3d)), endtime=now())\n        | where TimeGenerated > maxSummarizedTime\n        | summarize Count=count() by NetworkProtocol, DstPortNumber, DstAppName, NetworkDirection, DvcAction, bin(TimeGenerated,10m)\n        | extend EventTime = TimeGenerated, Count = toint(Count), DstPortNumber = toint(DstPortNumber), exists=int(1)\n        ) on exists\n        | project-away exists, maxv, nosum*\n    ),\n    (\n        (datatable(exists:int, nosum:bool)[1,false] | where toscalar(eps) <= 500 | join (nosummary) on nosum) | join (\n        _Im_NetworkSession(starttime=todatetime(ago(4d)), endtime=now())\n        | where TimeGenerated > maxSummarizedTime\n        | summarize Count=count() by NetworkProtocol, DstPortNumber, DstAppName, NetworkDirection, DvcAction, bin(TimeGenerated,10m)\n        | extend EventTime = TimeGenerated, Count = toint(Count), DstPortNumber = toint(DstPortNumber), exists=int(1)\n        ) on exists\n        | project-away exists, maxv, nosum*\n    ),\n    (\n        NetworkCustomAnalytics_protocol_CL\n        | where EventTime_t > ago(lookback)\n        | project-rename NetworkProtocol=NetworkProtocol_s, DstPortNumber=DstPortNumber_d, DstAppName=DstAppName_s, NetworkDirection=NetworkDirection_s, DvcAction=DvcAction_s, Count=count__d, EventTime=EventTime_t\n        | extend Count = toint(Count),DstPortNumber = toint(DstPortNumber) \n    )\n;\nallData\n| where isnotempty(DstPortNumber)\n| make-series Total=count() on EventTime from ago(lookback) to now() step 1d by DstPortNumber, NetworkProtocol, NetworkDirection, DvcAction\n| extend (anomalies, score, baseline) = series_decompose_anomalies(Total, AnomalyThreshold, -1, 'linefit')\n| mv-expand anomalies, score, baseline, EventTime, Total\n| extend anomalies = toint(anomalies), score = toint(score), baseline = toint(baseline), EventTime = todatetime(EventTime), Total = tolong(Total)\n| where EventTime >= ago(1d)\n| extend DstPortNumber = trim_end(\".0\",tostring(DstPortNumber))\n| where score > 2*AnomalyThreshold\n| join kind=inner ['mapping'] where Ports == DstPortNumber\n| where (Protocol == \"*\" or Protocol has NetworkProtocol)\n                and (Direction == \"*\" or Direction has NetworkDirection)\n                and (Action == \"*\" or Action has DvcAction)  \n| project Name, Description, NetworkProtocol, DstPortNumber, NetworkDirection, DvcAction, Severity, Tactic\n| summarize NetworkProtocols=make_set_if(NetworkProtocol,isnotempty(NetworkProtocol),20), \n                    NetworkDirections=make_set_if(NetworkDirection,isnotempty(NetworkDirection),5), \n                    DvcActions=make_set_if(DvcAction,isnotempty(DvcAction),10) by Name, Severity, Tactic, DstPortNumber, Description\n```"
---

