---
id: 277a8a9d-8f33-43ea-8977-0de619772d01
name: Remote Management and Monitoring tool - Panorama9 - Create Process
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceProcessEvents \n| where Timestamp between (Time_start..Time_end)\n| where ProcessVersionInfoCompanyName has 'panorama9'\n    or ProcessVersionInfoProductName has 'panorama9'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

