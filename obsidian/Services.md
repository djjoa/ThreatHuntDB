---
id: dd76f1c0-edc9-45cb-aeae-f5142caf583c
name: Services
description: |
  Gets the service name from the registry key.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
query: "```kusto\nDeviceRegistryEvents  \n| where RegistryKey has @\"SYSTEM\\CurrentControlSet\\Services\"\n| extend ServiceName=tostring(split(RegistryKey, @\"\\\")[4])\n| project Timestamp, DeviceName, ServiceName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessMD5, InitiatingProcessParentFileName\n| top 100 by Timestamp desc \n```"
---

