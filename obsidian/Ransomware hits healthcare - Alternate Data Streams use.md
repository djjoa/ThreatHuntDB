---
id: 90985951-5998-45d3-831f-8fd3c66ac9f9
name: Ransomware hits healthcare - Alternate Data Streams use
description: |
  Find use of Alternate Data Streams (ADS) for anti-forensic purposes.
  Alternate Data Streams execution.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d) \n// Command lines used \n| where ProcessCommandLine startswith \"-q -s\" and ProcessCommandLine has \"-p\" \n// Removing IDE processes \nand not(FolderPath has_any(\"visual studio\", \"ide\")) \n| summarize make_set(ProcessCommandLine), make_set(FolderPath), \nmake_set(InitiatingProcessCommandLine) by DeviceId, bin(Timestamp, 1h)\n```"
---

