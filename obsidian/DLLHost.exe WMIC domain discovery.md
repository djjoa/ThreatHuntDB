---
id: dc612ff9-88ac-4968-97c1-6789cd48c5d8
name: DLLHost.exe WMIC domain discovery
description: |
  Identify dllhost.exe using WMIC to discover additional hosts and associated domain.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Reconnaissance
query: "```kusto\nDeviceProcessEvents \n| where InitiatingProcessFileName =~ \"dllhost.exe\" and InitiatingProcessCommandLine == \"dllhost.exe\" \n| where ProcessCommandLine has \"wmic computersystem get domain\"\n```"
---

