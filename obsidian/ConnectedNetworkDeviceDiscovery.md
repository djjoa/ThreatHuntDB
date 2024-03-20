---
id: c7813a5c-ef11-4ee9-8feb-731402f31259
name: ConnectedNetworkDeviceDiscovery
description: "Find devices connected to a monitored network. \nPlease Note line 5 needs to have a monitored network name put in place or commented out to pull everything.\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
query: |-
  ```kusto
  DeviceNetworkInfo
  | mv-expand parse_json(IPAddresses)
  | mv-expand parse_json(ConnectedNetworks)
  | where IPAddresses.IPAddress !contains ":" and IPAddresses.IPAddress <> ""
  | where ConnectedNetworks.Name == "YourNetworkHere" and ConnectedNetworks.Name <> "" //Change the YourNetworkHere to the display
  | summarize arg_max(Timestamp, *) by DeviceName
  | project DeviceName, IPAddress=IPAddresses.IPAddress, ConnectedNetworks_value=ConnectedNetworks.Name
  ```
---

