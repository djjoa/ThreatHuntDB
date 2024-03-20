---
id: 3abb45d6-8514-4444-a7e4-6ab1c71ae5ce
name: Remote Management and Monitoring tool - SyncroMSP - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'syncromsp.com',\n        'servably.com',\n        'syncroapi.com'\n    )\n    and InitiatingProcessVersionInfoCompanyName has 'Servably, Inc.'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

