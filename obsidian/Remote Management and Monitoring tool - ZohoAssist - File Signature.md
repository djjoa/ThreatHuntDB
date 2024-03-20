---
id: ba1e02dc-2731-4f65-bdd3-b293e0490e9a
name: Remote Management and Monitoring tool - ZohoAssist - File Signature
description: |
  Remote Monitoring and Management (RMM) programs are IT to manage remote endpoints. Attackers have begun to abuse these programs to persist or provide C2 channels.
  https://github.com/jischell-msft/RemoteManagementMonitoringTools
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileCertificateInfo
tactics: CommandAndControl
relevantTechniques: T1219
query: "```kusto\nlet Time_start = now(-5d);\nlet Time_end = now();\n//\n// *Will return all binaries signed by Zoho, not just Zoho Assist*\n// \nDeviceFileCertificateInfo\n| where Timestamp between (Time_start..Time_end)\n| where Signer has 'Zoho'\n| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), \n    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName\n```"
---

