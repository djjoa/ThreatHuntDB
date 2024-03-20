---
id: 2cd90dd4-4f42-4d3e-86ed-b5c711f79f65
name: Remote Management and Monitoring tool - NAble - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'remote.management',\n        'logicnow.com',\n        'logicnow.us',\n        'system-monitor.com',\n        'systemmonitor.eu.com',\n        'systemmonitor.co.uk',\n        'systemmonitor.us',\n        'n-able.com',\n        'rmm-host.com',\n        'solarwindsmsp.com'\n    )\n    and InitiatingProcessVersionInfoCompanyName has_any (\n            'Remote Monitoring',\n            'LogicNow Ltd',\n            'N-Able',\n            'SolarWinds MSP'\n        )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

