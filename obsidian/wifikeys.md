---
id: ad5c7f75-95e0-4eb9-93e5-b1793ef405d6
name: wifikeys
description: |
  Detect if someone run netsh and try to expose WPA keys in clear text
  @mattiasborg82.
  Blog.sec-labs.com.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where ProcessCommandLine startswith \"netsh\"\n| where ProcessCommandLine has \"key=clear\"\n| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine\n| top 100 by Timestamp\n```"
---

