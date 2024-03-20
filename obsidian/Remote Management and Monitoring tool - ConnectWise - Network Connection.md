---
id: e483619f-5356-4967-b93e-cceb602783fb
name: Remote Management and Monitoring tool - ConnectWise - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        \"myconnectwise.com\",\n        \"connectwise.com\",\n        \"screenconnect.com\",\n        \"itsupport247.net\"  // overlap w/ Continuum Managed\n    )\n    and InitiatingProcessVersionInfoCompanyName has_any (\n        'ConnectWise', \n        'Continuum Managed', \n        'ScreenConnect'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

