---
id: b194088b-c846-4c72-a4b7-933627878db4
name: Potential Maldoc Execution Chain Observed
description: |
  'Detect the aftermath of a successfully delivered and executed maldoc (Microsoft Office). Indicates an Office document was opened from an email or download/link, spawned a suspicious execution, and attempted to execute code via common Windows binaries.'
requiredDataConnectors:
  - connectorId: SecurityEvent
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
  - Execution
  - InitialAccess
relevantTechniques:
  - T1059
  - T1059.001
  - T1059.004
  - T1059.005
  - T1059.006
  - T1059.007
  - T1218.011
  - T1566.001
  - T1566.002
query: |-
  ```kusto
  let officeProducts = dynamic(["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","MSACCESS.EXE","VISIO.EXE","WINPROJ.EXE"]);
  let executionMethods = dynamic(["powershell.exe","cmd.exe","WScript.exe","rundll32.exe","cscript.exe","wmic.exe","mshta.exe","msiexec.exe"]);
  SecurityEvent
  | where TimeGenerated >= ago(7d)
  | where (NewProcessName has_any (officeProducts,"OUTLOOK.EXE","explorer.exe",executionMethods) or ParentProcessName has_any (officeProducts,"OUTLOOK","explorer",executionMethods))
  | project TimeGenerated, Computer, Activity, EventID, CommandLine, NewProcessName, processId = tolong(NewProcessId), ParentProcessName, parentProcessId = tolong(ProcessId)
  | extend sourceAppTrue=case(NewProcessName endswith "outlook.exe",1,
                              (ParentProcessName has_any("outlook.exe","explorer.exe") and NewProcessName has_any(officeProducts)),1,
                              0)
  | extend officeAppTrue=case(NewProcessName has_any(officeProducts),1,
                              ParentProcessName has_any(officeProducts),1,
                              0)
  | extend executionTrue=case(NewProcessName has_any(executionMethods),1,
                              ParentProcessName has_any(executionMethods),1,
                              0)
  | summarize process=make_set(NewProcessName,10), processId=make_set(processId,10), parentProcess=make_set(ParentProcessName,10),parentProcessId=make_set(parentProcessId,10), sourceApp=sum(sourceAppTrue), officeApp=sum(officeAppTrue), execution=sum(executionTrue)
  by Computer, bin(TimeGenerated,5m)
  | where sourceApp > 0 and officeApp > 0 and execution > 0
  ```
version: 1.0.0
---

