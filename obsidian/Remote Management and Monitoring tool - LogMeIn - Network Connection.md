---
id: e1f849f9-1218-4990-964d-dd8c69897107
name: Remote Management and Monitoring tool - LogMeIn - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has_any (\n        'update-cdn.logmein.com',\n        'secure.logmein.com',\n        'update.logmein.com',\n        'logmeinrescue.com',\n        'logmeinrescue.eu',\n        'logmeinrescue-enterprise.com',\n        'logmeinrescue-enterprise.eu',\n        'remotelyanywhere.com',\n        'gotoassist.com',\n        'logmeininc.com',\n        'logme.in',\n        'getgo.com',\n        'goto.com',\n        'goto-rtc.com',\n        'gotomypc.com'\n    )\n    and InitiatingProcessVersionInfoCompanyName has_any ('LogMeIn', 'GoTo')\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

