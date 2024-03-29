---
id: 4e339200-6a5a-4e83-8ba4-87acee0bd518
name: Remote Management and Monitoring tool - AweSun - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl  has_any (\n        \"aweray.com\",\n        \"aweray.net\",\n        \"awerayimg.com\",\n        \"awesun.app\"\n    )\n    and InitiatingProcessVersionInfoCompanyName has 'AweRay'\n    and InitiatingProcessVersionInfoProductName has 'AweSun'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

