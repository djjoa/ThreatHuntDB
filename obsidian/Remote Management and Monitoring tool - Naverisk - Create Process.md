---
id: 3063ab0b-a34c-42f2-bcdd-8c5974cc47fd
name: Remote Management and Monitoring tool - Naverisk - Create Process
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceProcessEvents \n| where Timestamp between (Time_start..Time_end)\n| where ProcessVersionInfoCompanyName has_any (\n        'naverisk', \n        'NavMK1 Limited'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

