---
id: b00595db-ba89-48d8-bdf2-77b18c6be7ac
name: Remote Management and Monitoring tool - AeroAdmin - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has 'aeroadmin.com'\n    and InitiatingProcessVersionInfoCompanyName has_any  ('AeroAdmin', 'Aero Admin')\n    and InitiatingProcessVersionInfoProductName has_any  ('AeroAdmin', 'Aero Admin')\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

