---
id: 67309406-12ad-4591-84db-0cc331634d0c
name: Windows Spooler Service Suspicious File Creation
description: "The query digs in Windows print spooler drivers folder for any file creations,\nMANY OF THE FILES THAT SHOULD COME UP HERE MAY BE LEGIT. Suspicious DLL is load from Spooler Service backup folder. \nThis behavior is used from PoC Exploit of CVE-2021-34527, CVE-2021-1675 or CVE-2022-21999.\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - Privilege escalation
  - Lateral movement
  - Exploit
relevantTechniques:
  - t1574
query: |-
  ```kusto
  DeviceFileEvents
  | where Timestamp > ago(7d)
  | where ActionType == "FileCreated"
  | where FileName endswith ".dll"
  | where FolderPath startswith "C:\\WINDOWS\\SYSTEM32\\SPOOL\\drivers\\x64\\\3\\"
     or FolderPath startswith "C:\\WINDOWS\\SYSTEM32\\SPOOL\\drivers\\x64\\\4\\"
  ```
---
