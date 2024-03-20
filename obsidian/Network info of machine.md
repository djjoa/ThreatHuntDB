---
id: 86fb56b4-3a10-443b-8345-d00a45046d15
name: Network info of machine
description: |
  Get information about the netwotk adapters of the given computer in the given time.
  This could include the configured IP addresses, DHCP servers, DNS servers, and more.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkInfo
query: "```kusto\nlet DeviceIdParam = \"c0bfefec0bfefec0bfefec0bfefec0bfefecafe\";\nlet pivotTimeParam = datetime(2018-07-15T19:51);\nDeviceNetworkInfo\n// Query for reports sent +-15 minutes around the time we are interested in\n| where Timestamp between ((pivotTimeParam-15m) .. 30m) and DeviceId == DeviceIdParam and NetworkAdapterStatus == \"Up\"\n// IPAddresses contains a list of the IP addresses configured on the network adapter, their subnets, and more.\n// Here we expand the list so that each value gets a separate row. All the other columns in the row, such as MacAddress, are duplicated.\n| mvexpand parse_json(IPAddresses)\n| project IPAddress=IPAddresses.IPAddress, AddressType=IPAddresses.AddressType, NetworkAdapterType, TunnelType, MacAddress, \nConnectedNetworks, Timestamp, TimeDifference=abs(Timestamp-pivotTimeParam)\n// In case multiple machines have reported from that IP address arround that time, start with the ones reporting closest to pivotTimeParam\n| sort by TimeDifference asc, NetworkAdapterType, MacAddress\n```"
---

