---
id: dab99d96-b53d-438f-9826-fd0934e8578c
name: Seen IPv6 Network Subnets
description: |
  This query uncovers seen IPAddressV6 network subnets
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
tactics: []
relevantTechniques: []
query: "```kusto\n// \nDeviceNetworkInfo\n| summarize arg_max(Timestamp, *) by DeviceId\n| mv-expand todynamic(IPAddresses)\n| where isnotempty( IPAddresses.SubnetPrefix) and isnotempty( IPAddresses.IPAddress)\n| extend Subnet = parse_ipv6_mask(tostring(IPAddresses.IPAddress), toint(IPAddresses.SubnetPrefix))\n| summarize by Subnet\n```"
---

