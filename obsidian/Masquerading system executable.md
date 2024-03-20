---
id: e1528e63-165f-4810-b2eb-24a181a3011e
name: Masquerading system executable
description: |
  Finds legitimate system32 or syswow64 executables being run under a different name and in a different location.
  The rule will require tuning for your environment.
  MITRE: Masquerading https://attack.mitre.org/techniques/T1036.
  Get a list of all processes run, except those run from system32 or SysWOW64.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nlet nonSystemProcesses = \n    DeviceProcessEvents \n    | where Timestamp > ago(7d) //Adjust your desired date range here and set the data/time picker to 30 days \n    | where FolderPath !startswith @\"C:\\Windows\\system32\\\" and FolderPath !startswith @\"C:\\Windows\\SysWOW64\\\" and isnotempty(MD5)\n    and FileName !in~ (\"MpSigStub.exe\",\"GACUtil_20.exe\");\n//Get a list of MD5s of all procceses run from system32 or SysWOW64\nlet systemProcessHashes = \n    DeviceProcessEvents \n    | where Timestamp > ago(30d) //Keep this at 30 days so it uses all available data to compile the list of hashes\n    | where FolderPath startswith @\"C:\\Windows\\system32\\\" or FolderPath startswith @\"C:\\Windows\\SysWOW64\\\" and isnotempty(MD5) \n    and FileName !in~ (\"fileacl.exe\",\"WerFault.exe\")\n    | summarize LegitFolderPath=makeset(tolower(FolderPath)) by MD5, LegitFileName=FileName;\n//Join the two tables on MD5, where the filenames do not match\nsystemProcessHashes | join kind=inner (nonSystemProcesses) on MD5 | where tolower(LegitFileName)!=tolower(FileName)\n| project Timestamp, DeviceName, FileName, FolderPath, LegitFileName, LegitFolderPath, MD5, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, ReportId, DeviceId\n| top 100 by Timestamp desc\n```"
---

