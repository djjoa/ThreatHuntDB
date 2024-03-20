---
id: 30d32feb-6ac7-4d97-8a99-d40f5dfa61b5
name: Remote Management and Monitoring tool - RemotePC - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has 'remotepc.com'\n    and InitiatingProcessVersionInfoCompanyName has 'idrive'\n    and InitiatingProcessVersionInfoProductName has_any (\n        'remotepc',\n        'viewer',\n        'remotedesktop'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

