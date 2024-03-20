---
id: 65d15781-c7bf-447e-8c33-a2a94e727bf4
name: Deletion of data on multiple drives using cipher exe
description: |
  This query checks for attempts to delete data on multiple drives using cipher.exe. This activity is typically done by ransomware to prevent recovery of data after encryption.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\n// Look for cipher.exe deleting data from multiple drives\nDeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName =~ \"cipher.exe\" \n// cipher.exe /w flag used for deleting data \n| where ProcessCommandLine has \"/w\" \n| summarize CipherCount = dcount(ProcessCommandLine),\nCipherList = make_set(ProcessCommandLine) by DeviceId, bin(Timestamp, 1m) \n// cipher.exe accessing multiple drives in a short timeframe \n| where CipherCount > 1\n```"
---

