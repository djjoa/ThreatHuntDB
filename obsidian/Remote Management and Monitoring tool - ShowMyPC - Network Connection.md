---
id: 9074b61c-76e2-4793-ad48-0e9226c35c3e
name: Remote Management and Monitoring tool - ShowMyPC - Network Connection
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceNetworkEvents\n| where Timestamp between (Time_start..Time_end)\n| where RemoteUrl has 'showmypc.com'\n    and InitiatingProcessVersionInfoCompanyName has 'ShowMyPC'\n    and InitiatingProcessVersionInfoProductName has 'ShowMyPC'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,\n    RemoteUrl \n```"
---

