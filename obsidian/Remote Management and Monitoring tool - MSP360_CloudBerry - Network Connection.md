---
id: 3a4d43d5-2326-467c-a22a-4f1f1f3e2890
name: Remote Management and Monitoring tool - MSP360_CloudBerry - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'rm.mspbackups.com',\n        'client.rmm.mspbackups.com',\n        'settings.services.mspbackups.com',\n        'connect.ra.msp360.com',\n        'foris.cloudberrylab.com'\n    )\n    and InitiatingProcessVersionInfoCompanyName has_any (\n        'CloudBerry',\n        'MSP360'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

