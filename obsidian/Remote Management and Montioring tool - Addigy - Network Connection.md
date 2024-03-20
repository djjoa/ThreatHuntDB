---
id: 4f0b3b8d-bde4-4cce-9ff7-1f0c0a7085af
name: Remote Management and Montioring tool - Addigy - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'prod.addigy.com',\n        'grtmprod.addigy.com',\n        'agents.addigy.com'\n    )\n    and InitiatingProcessFileName has_any (\n        'go-agent',\n        'auditor',\n        'collector',\n        'xpcproxy',\n        'lan-cache',\n        'mdmclient',\n        'launchd'\n    )\n    and isempty(InitiatingProcessVersionInfoCompanyName)\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

