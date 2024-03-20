---
id: 62263920-ab21-4fc6-84ce-00ca4360c091
name: Remote Management and Monitoring tool - BarracudaRMM - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'rmm.barracudamsp.com',\n        'content.ivanti.com' // Backup solution used by Barracuda MSP\n    )\n    and InitiatingProcessVersionInfoCompanyName has_any (\n        'Barracuda MSP',\n        'LPI Level Platforms'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

