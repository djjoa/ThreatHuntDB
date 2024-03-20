---
id: b915897c-1fe7-47f4-9e06-2ae74da8203e
name: Remote Management and Monitoring tool - ZohoAssist - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'assist.zoho.com',\t\t\t\n        'assist.zoho.eu',\t\t\t\n        'assist.zoho.com.au',\t\t\n        'assist.zoho.in',\t\t\t\n        'assist.zoho.jp', \t\t\t\n        'assist.zoho.uk',\t\t\t\n        'assistlab.zoho.com',\t\t\n        'downloads.zohocdn.com',\t\n        'download-accl.zoho.in',\t\n        'zohoassist.com',\t\t\t\n        'zohopublic.com',\t\t\t\n        'zohopublic.eu',\t\t\t\n        'meeting.zoho.com',\t\t\t\n        'meeting.zoho.eu', \t\t\t\n        'static.zohocdn.com',\t\t\n        'zohodl.com.cn',\t\t\t\n        'zohowebstatic.com',\t\t\n        'zohostatic.in'\t\t\n    )\n    and InitiatingProcessVersionInfoCompanyName has 'Zoho'\n    and InitiatingProcessVersionInfoProductName has 'Zoho Assist'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

