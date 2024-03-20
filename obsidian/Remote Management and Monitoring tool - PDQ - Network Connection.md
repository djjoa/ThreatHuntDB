---
id: 58cbbe97-f835-4677-9bee-203b1df29600
name: Remote Management and Monitoring tool - PDQ - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'app.pdq.com',\n        'connect-package-library.e9d69694c3d8f7465fd531512c22bd0f.r2.cloudflarestorage.com',\n        'connect.e9d69694c3d8f7465fd531512c22bd0f.r2.cloudflarestorage.com',\n        'cfcdn.pdq.com'\n    )\n    and InitiatingProcessVersionInfoProductName has 'PDQConnectAgent'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

