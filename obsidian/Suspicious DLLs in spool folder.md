---
id: cabb3aa3-cbfa-4359-9464-a3093d8b44f3
name: Suspicious DLLs in spool folder
description: |
  Look for the creation of suspicious DLL files spawned in the \spool\ folder along with DLLs that were recently loaded afterwards from \Old.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceImageLoadEvents
tactics:
  - Privilege escalation
  - Exploit
query: "```kusto\nDeviceFileEvents\n| where FolderPath contains @\"\\system32\\spool\\drivers\\x64\\3\\\"\n| where FileName endswith \".dll\"\n| where ActionType in (\"FileCreated\", \"FileRenamed\")\n| join kind=inner DeviceImageLoadEvents on DeviceId,DeviceName,FileName,InitiatingProcessFileName\n| where Timestamp1 >= Timestamp and FolderPath1 contains @\"\\system32\\spool\\drivers\\x64\\3\\Old\" \n```"
---

