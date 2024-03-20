---
id: 007fcd0d-38c8-44a9-be56-827c4d57b150
name: Remote Management and Monitoring tool - AweSun - Create Process
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceProcessEvents \n| where Timestamp between (Time_start..Time_end)\n| where ProcessVersionInfoCompanyName has 'AweRay'\n    and ProcessVersionInfoProductName has 'AweSun'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

