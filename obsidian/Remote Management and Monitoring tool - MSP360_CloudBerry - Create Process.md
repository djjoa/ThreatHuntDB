---
id: 2ed71614-0c21-4a41-962a-386234d5d000
name: Remote Management and Monitoring tool - MSP360_CloudBerry - Create Process
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceProcessEvents \n| where Timestamp between (Time_start..Time_end)\n| where ProcessVersionInfoCompanyName has_any (\n        'CloudBerry',\n        'MSP360'\n    )\n    and ProcessVersionInfoProductName has_any (\n        'RMM',\n        'Remote',\n        'Connect',\n        'Cloud.Ra',\n        'RM Service'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

