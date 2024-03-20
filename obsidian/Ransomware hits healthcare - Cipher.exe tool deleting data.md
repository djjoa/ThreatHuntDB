---
id: afef7d05-0618-4bd7-9fbc-2e94ee764245
name: Ransomware hits healthcare - Cipher.exe tool deleting data
description: |
  // Look for cipher.exe deleting data from multiple drives.
  This is often performed as an anti-forensic measure prior to encryption.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)  \n| where FileName =~ \"cipher.exe\"  \n// Looking for /w flag for deleting  \n| where ProcessCommandLine has \"/w\"  \n| summarize CommandCount = dcount(ProcessCommandLine), \nmake_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 1m)  \n// Looking for multiple drives in a short timeframe  \n| where CommandCount > 1\n```"
---

