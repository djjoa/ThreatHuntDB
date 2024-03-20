---
id: d7c16186-57d3-4e65-bd6b-f333d97d0c15
name: Remote Management and Monitoring tool - BeyondTrust - File Signature
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileCertificateInfo
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceFileCertificateInfo\n| where Timestamp between (Time_start..Time_end)\n| where Signer has_any (\n        'Bomgar Corporation',\n        'BeyondTrust Corporation',\n        'BeyondTrust Software'\n    )\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

