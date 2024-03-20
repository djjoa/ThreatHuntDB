---
id: 919047fa-f646-469a-bfeb-69a0dcbf44c0
name: Seen IPv4 Network Subnets
description: |
  This query uncovers seen IPAddressV4 network subnets
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
tactics: []
relevantTechniques: []
query: "```kusto\n// \nDeviceNetworkInfo\n| summarize arg_max(Timestamp, *) by DeviceId\n| mv-expand todynamic(IPAddresses)\n| where isnotempty( IPAddresses.SubnetPrefix) and isnotempty( IPAddresses.IPAddress)\n| extend Subnet = format_ipv4_mask(tostring(IPAddresses.IPAddress), toint(IPAddresses.SubnetPrefix))\n| summarize by Subnet\n```"
---

