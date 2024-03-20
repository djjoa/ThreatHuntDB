---
id: 088d30e9-c02b-46b1-bd1f-d5b6d6b782f0
name: Least Common Processes by Command Line
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
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 7d;  \nlet Allowlist = dynamic (['foo.exe', 'baz.exe']);\nlet Sensitivity = 5;  \nSecurityEvent\n| where TimeGenerated between(lookback..endtime)\n| where EventID == 4688 and NewProcessName !endswith 'conhost.exe'\n| extend ProcArray = split(NewProcessName, '\\\\')\n// ProcArrayLength is Folder Depth\n| extend ProcArrayLength = array_length(ProcArray)\n| extend LastIndex = ProcArrayLength - 1\n| extend Proc = ProcArray[LastIndex]\n| where Proc !in (Allowlist)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), TimesSeen = count(), HostCount = dcount(Computer), Hosts = make_set(Computer,maxSize=500), UserCount = dcount(SubjectUserName), Users = make_set(SubjectUserName,maxSize=500) by CommandLine\n| where TimesSeen < Sensitivity\n| extend timestamp = StartTimeUtc\n```"
version: 2.0.1
---

