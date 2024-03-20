---
id: a3dc6ecb-d910-467b-844e-a3b87744c4c9
name: SMB shares discovery
description: |
  Query for processes that accessed more than 10 IP addresses over port 445 (SMB) - possibly scanning for network shares.
  To read more about Network Share Discovery, see: https://attack.mitre.org/wiki/Technique/T1135.
  Tags: #SMB, #NetworkScanning, #UniqueProcessId.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
query: "```kusto\nDeviceNetworkEvents\n| where RemotePort == 445 and Timestamp > ago(7d) \n    // Exclude Kernel processes, as they are too noisy in this query\n    and InitiatingProcessId !in (0, 4)\n| summarize RemoteIPCount=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime\n| where RemoteIPCount > 10\n```"
---

