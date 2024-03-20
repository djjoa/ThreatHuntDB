---
id: c75a64e3-2849-4342-a115-7cc6f009b520
name: Remote Management and Monitoring tool - Kaseya - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'kaseya.com',\t\t\t\t\n        'stun.kaseya.com',\t\t\t\n        'managedsupport.kaseya.net',\n        'kaseya.net'\n    )\n    and InitiatingProcessVersionInfoCompanyName has 'Kaseya'\n    and InitiatingProcessVersionInfoProductName has 'Kaseya'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

