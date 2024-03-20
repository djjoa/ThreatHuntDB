---
id: 42ee6265-ed2d-42b6-9c69-095092dce2e3
name: Remote Management and Monitoring tool - Level - Create Process
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceProcessEvents \n| where Timestamp between (Time_start..Time_end)\n| where FileName startswith \"level\"\n    and FolderPath has_any (\n        @'\\Program Files\\Level\\', \n        @'\\Program Files (x86)\\Level\\'\n    )\n    and isempty(ProcessVersionInfoCompanyName)\n    and isempty(ProcessVersionInfoProductName)\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

