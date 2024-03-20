---
id: 6d04a1ef-1b4d-4ff8-a76c-ad7d1a396136
name: Least Common Processes Including Folder Depth
description: |
  'Looks across your environment for least common Process Command Lines, may be noisy and require allowlisting.  By ZanCo'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 7d;  \nlet Allowlist = dynamic (['foo.exe', 'baz.exe']);\nlet Sensitivity = 15;\nSecurityEvent\n| where TimeGenerated between(lookback..endtime)\n| where EventID == 4688\n| extend ProcArray = split(NewProcessName, '\\\\')\n// ProcArrayLength is Folder Depth\n| extend ProcArrayLength = array_length(ProcArray)\n| extend LastIndex = ProcArrayLength - 1\n| extend Proc = ProcArray[LastIndex]\n| where Proc !in (Allowlist)\n// ProcArray[0] is the proc's Drive\n| extend DriveDepthProc = strcat(ProcArray[0], '-', ProcArrayLength, '-', Proc)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = make_set(Computer,maxSize=2000), UserCount = dcount(SubjectUserName), Users = make_set(SubjectUserName,maxSize=2000) by DriveDepthProc\n| where TimesSeen < Sensitivity\n| extend timestamp = StartTimeUtc\n```"
version: 2.0.1
---

