---
id: 374a40ba-73fc-4d70-95ac-524b5765ffa2
name: Summary of users created using uncommon/undocumented commandline switches (Normalized Process Events)
description: |
  'Summarizes uses of uncommon & undocumented commandline switches to create persistence
  User accounts may be created to achieve persistence on a machine.
  Read more here: https://attack.mitre.org/wiki/Technique/T1136
  Query for users being created using "net user" command
  "net user" commands are noisy, so needs to be joined with another signal -
  e.g. in this example we look for some undocumented variations (e.g. /ad instead of /add)'
requiredDataConnectors: []
tactics:
  - CredentialAccess
  - LateralMovement
relevantTechniques:
  - T1110
query: "```kusto\nimProcessCreate\n| where Process has_any (\"net.exe\", \"net1.exe\") // preformance pre-filtering\n| extend FileName = tostring(split(Process, '\\\\')[-1]) \n| extend ActingProcessFileName= tostring(split(ActingProcessName, '\\\\')[-1]) \n| where FileName in~ (\"net.exe\", \"net1.exe\")\n| parse kind=regex flags=iU CommandLine with * \"user \" CreatedUser \" \" * \"/ad\"\n| where not(FileName =~ \"net1.exe\" and ActingProcessFileName =~ \"net.exe\" and replace(\"net\", \"net1\", ActingProcessCommandLine) =~ CommandLine)\n| extend CreatedOnLocalMachine=(CommandLine !has \"/do\")\n| where CommandLine has \"/add\" or (CreatedOnLocalMachine == 0 and CommandLine !has \"/domain\")\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), MachineCount=dcount(Dvc) by CreatedUser, CreatedOnLocalMachine, ActingProcessFileName, FileName, CommandLine, ActingProcessCommandLine, EventVendor, EventProduct\n| extend timestamp = StartTimeUtc, AccountCustomEntity = CreatedUser\n```"
---

