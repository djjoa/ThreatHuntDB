---
id: 3e571521-6f73-423f-9280-aff6170c9d81
name: OceanLotus registry activity
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_oceanlotus_registry.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceRegistryEvents
query: "```kusto\nDeviceRegistryEvents \n| where Timestamp > ago(7d)\n| where ActionType == \"RegistryValueSet\" \n| where RegistryKey endswith @\"\\SOFTWARE\\Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application\" \n     or RegistryKey endswith @\"\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon\"\n```"
---

