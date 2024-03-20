---
id: 1f80f1cf-97e1-4fb8-ad5a-e573fac7b9e3
name: File footprint (1)
description: |
  Query #1 - Find the machines on which this file was seen.
  TODO - set file hash to be a SHA1 hash of your choice...
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
query: "```kusto\n// Query # 2 - Shows you a list of distinct IP addresses and DNS names the endpoint had network communication with through a specific file. \n// Use this list to whitelist/blacklist IP addresses or understand if there are communication with IP you are not aware of.\n// Update the filename to the name you wish to investigate network communication.\nlet filename = \"FILENAME GOES HERE\";\n// Builds table for distinct URLs based off filename\nDeviceNetworkEvents \n| where InitiatingProcessFileName =~ filename and ( isnotempty(RemoteIP) or isnotempty(RemoteUrl) )\n| project DNS=RemoteUrl, IP=RemoteIP\n| distinct IP, DNS\n```"
---

