---
id: 10838671-0c35-4d5b-95f8-06d5b4d5bf61
name: Map external devices
description: |
  Action "PnpDeviceConnected" reports the connection of any plug and play device.
  Read more online on event 6416: https://docs.microsoft.com/windows/security/threat-protection/auditing/event-6416.
  Query #1: look for rare one-time devices connected to a specific machine.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
query: "```kusto\nlet DeviceNameParam = \"<replace this with full computer name>\";\n// Query for device connection events\nlet devices =\n    DeviceEvents\n    | where ActionType == \"PnpDeviceConnected\"\n    | extend parsed=parse_json(AdditionalFields)\n    | project \n        DeviceDescription=tostring(parsed.DeviceDescription),\n        ClassName=tostring(parsed.ClassName),\n        DeviceId=tostring(parsed.VendorIds),\n        VendorIds=tostring(parsed.VendorIds),\n        DeviceName, Timestamp ;\n// Filter devices seen on the suspected machine\ndevices | where DeviceName == DeviceNameParam\n// Get some stats on the device connections to that machine\n| summarize TimesConnected=count(), FirstTime=min(Timestamp), LastTime=max(Timestamp) by DeviceId, DeviceDescription, ClassName, VendorIds, DeviceName\n// Optional filter - looking for devices used in only within 24h\n| where LastTime - FirstTime < 1d\n// Filter out (antijoin) devices that are common in the organization.\n// We use here multiple identifiers, including a pseudo-unique device ID.\n// So, a specific disk-on-key device which model is common in the org will still be shown in the results,\n// while built-in software devices (often have constant device ID) as well as common network devices (e.g. printer queues) will be excluded.\n| join kind=leftanti \n  (devices | summarize Machines=dcount(DeviceName) by DeviceId, DeviceDescription, VendorIds | where Machines > 5)\n  on DeviceId, DeviceDescription, VendorIds\n```"
---

