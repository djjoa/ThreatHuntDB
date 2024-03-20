---
id: 41a9931d-8cb4-44dc-9c8d-f915dd15dfd8
name: Remote Management and Monitoring tool - DattoRMM - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'rmm.datto.com',\n        'agent.centrastage.net',\n        'audit.centrastage.net',\n        'monitoring.centrastage.net',\n        'agent-notifications.centrastage.net',\n        'agent-comms.centrastage.net',\n        'update.centrastage.net',\n        'realtime.centrastage.net',\n        'ts.centrastage.net'\n    )\n    and ( \n        InitiatingProcessVersionInfoCompanyName has_any ('CentraStage', 'Datto', 'Kaseya' )\n    or isempty(InitiatingProcessVersionInfoCompanyName)\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

