---
id: 3712595d-6f47-416b-963a-605201ed2764
name: Least Common Parent And Child Process Pairs
description: |
  'Looks across your environment for least common Parent/Child process combinations.
  Will possibly find some malicious activity disguised as well known process names.
  By ZanCo'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 7d;\nlet Allowlist = dynamic (['foo.exe', 'baz.exe']);\nlet Sensitivity = 5;\nSecurityEvent\n| where TimeGenerated between(lookback..endtime)\n| where EventID == 4688 and isnotempty(ParentProcessName)  \n| extend ProcArray = split(NewProcessName, '\\\\'), ParentProcArray = split(ParentProcessName, '\\\\')\n// ProcArrayLength is Folder Depth\n| extend ProcArrayLength = array_length(ProcArray), ParentProcArrayLength = array_length(ParentProcArray)\n| extend LastIndex = ProcArrayLength - 1, ParentLastIndex = ParentProcArrayLength - 1\n| extend Proc = ProcArray[LastIndex], ParentProc = ParentProcArray[ParentLastIndex]\n| where Proc !in (Allowlist)\n| extend ParentChildPair = strcat(ParentProc , ' > ', Proc)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = make_set(Computer,maxSize=1000), UserCount = dcount(SubjectUserName), Users = make_set(SubjectUserName,maxSize=1000) by ParentChildPair\n| where TimesSeen < Sensitivity\n| extend timestamp = StartTimeUtc\n```"
version: 2.0.1
---

