---
id: 49cf658e-f446-476e-a7da-30909caaa3e3
name: Machine info from IP address (1)
description: |
  The following queries pivot from an IP address assigned to a machine to the relevant machine or logged-on users.
  To read more about it, check out this post: https://techcommunity.microsoft.com/t5/What-s-New/Advanced-hunting-now-includes-network-adapters-information/m-p/224402#M74.
  Query #1: get machines that have used a given local IP address at a given time - as configured on their network adapters.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
      - DeviceInfo
query: "```kusto\n// Query #2:\n// same as query #1 (get machines that have used a given local IP address at a given time), but also query for the logged on user\nlet pivotTimeParam = datetime(2018-07-15 19:51:00);\nlet ipAddressParam = \"192.168.1.5\";\nlet matchingMachines = \n    DeviceNetworkInfo\n    | where Timestamp between ((pivotTimeParam-15m) ..30m) and IPAddresses contains strcat(\"\\\"\", ipAddressParam, \"\\\"\") and NetworkAdapterStatus == \"Up\"\n    //// Optional - add filters to make sure machine is part of the relevant network (and not using that IP address as part of another private network).\n    //// For example:\n    // and ConnectedNetworks contains \"corp.contoso.com\"\n    // and IPv4Dhcp == \"10.164.3.12\"\n    // and DefaultGateways contains \"\\\"10.164.3.1\\\"\"\n    | project DeviceName, Timestamp, IPAddresses, TimeDifference=abs(Timestamp-pivotTimeParam);\nDeviceInfo\n| where Timestamp between ((pivotTimeParam-15m) ..30m)\n| project DeviceName, Timestamp, LoggedOnUsers \n| join kind=inner (matchingMachines) on DeviceName, Timestamp\n| project Timestamp, DeviceName, LoggedOnUsers, TimeDifference, IPAddresses\n// In case multiple machines have reported from that IP address arround that time, start with the ones reporting closest to pivotTimeParam\n| sort by TimeDifference asc\n```"
---

