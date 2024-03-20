---
id: cd1492a0-7e53-4615-9e63-f930576a3f6b
name: Seen Connected Networks
description: |
  This query uncovers seen connected networks
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
tactics: []
relevantTechniques: []
query: "```kusto\n// \nDeviceNetworkInfo\n| summarize arg_max(Timestamp, *) by DeviceId\n| mv-expand todynamic(ConnectedNetworks)\n| where isnotempty( ConnectedNetworks.Name)\n| summarize by NetworkNames = tostring(ConnectedNetworks.Name)\n```"
---

