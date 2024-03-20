---
id: 61660f4e-45e0-4ac4-8957-580bcebd033c
name: Remote Management and Monitoring tool - AnyViewer - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        \"anyviewer.com\", \n        \"anyviewer.cn\", \n        \"aomeisoftware.com\", \n        \"aomeikeji.com\"\n    )\n    and InitiatingProcessVersionInfoCompanyName has 'AOMEI'\n    and InitiatingProcessVersionInfoProductName has 'AnyViewer'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

