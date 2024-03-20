---
id: d3123681-8eed-4a6d-b0c0-05d0075e3e69
name: Discovery for highly-privileged accounts
description: |
  Use this query to locate commands related to discovering highly privileged users in an environment, sometimes a precursor to ransomware
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Discovery
  - Ransomware
query: "```kusto\nDeviceProcessEvents\n| where FileName == \"net.exe\"\n// Create a set for the command lines\n| summarize makeset(ProcessCommandLine) by InitiatingProcessFileName, AccountName, DeviceId, bin(Timestamp, 5m)\n// Other process launches by Net in that same timeframe\n| where (set_ProcessCommandLine has \"admin\" \nand set_ProcessCommandLine has_any(\"domain\", \"enterprise\", \"backup operators\"))\nand set_ProcessCommandLine has \"group\" and set_ProcessCommandLine contains \"/do\"\n```"
---

