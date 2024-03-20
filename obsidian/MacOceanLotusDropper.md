---
id: 1b7f5ba1-6712-4d74-ab88-182932b6af0d
name: MacOceanLotusDropper
description: |
  Backdoor processes associated with OceanLotus Mac malware backdoor dropper.
  References:.
  Https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-backdoor-linked-to-oceanlotus-found/.
  OS Platforms: Macintosh.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents\n| where Timestamp > ago(14d)\n| where ProcessCommandLine contains \"theme0\" \n| project Timestamp, DeviceId , DeviceName, AccountName , AccountSid , InitiatingProcessCommandLine , ProcessCommandLine  \n| top 100 by Timestamp \n```"
---

