---
id: 664afd0d-c979-4970-affe-fc17f01276fb
name: Suspicious files in spool folder
description: |
  Monitor for creation of suspicious files in the /spools/driver/ folder. This is a broad-based search that will surface any creation or modification of files in the folder targeted by this exploit. False Positives for legitimate driver activity (when that activity should be present) in this folder are possible
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - Privilege escalation
  - Exploit
query: |-
  ```kusto
  DeviceFileEvents
  | where FolderPath has @"System32\spool\drivers"
  | project DeviceName,Timestamp,ActionType,FolderPath,FileName,SHA1
  ```
---
