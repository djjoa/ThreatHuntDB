---
id: 625dce50-2fec-4f49-be92-ad4cab98b313
name: MosaicLoader
description: |
  This hunting query looks Malware Hides Itself Among Windows Defender Exclusions to Evade Detection
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
tactics:
  - Command and control
query: "```kusto\nDeviceRegistryEvents \n| where ((ActionType == \"RegistryValueSet\") and (RegistryKey startswith @\"HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\Paths\" \nor RegistryKey startswith @\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\"\nor RegistryKey startswith @\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\"))\n```"
---

