---
id: b702180d-9a11-412d-b18f-74b72520bb47
name: Remote Management and Monitoring tool - AweSun - File Signature
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileCertificateInfo
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\nDeviceFileCertificateInfo\n| where Timestamp between (Time_start..Time_end)\n| where Signer has_any ('aweray limited', 'aweray pte. ltd.')\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---
