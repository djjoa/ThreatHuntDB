---
id: 679e3086-4871-481f-92a6-5d3357d7f6bb
name: Remote Management and Monitoring tool - DameWare - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        \"swi-rc.com\",\n        \"swi-tc.com\",\n        \"beanywhere.com\",\n        \"licenseserver.solarwinds.com\"\n    )\n    and InitiatingProcessVersionInfoCompanyName  has_any ('DameWare', 'SolarWinds')\n    and \n    (\n        InitiatingProcessVersionInfoProductName has 'DameWare'\n        or \n        InitiatingProcessVersionInfoFileDescription has 'DameWare'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

