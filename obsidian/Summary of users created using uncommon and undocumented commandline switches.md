---
id: 5e76eaf9-79a7-448c-bace-28e5b53b8396
name: Summary of users created using uncommon/undocumented commandline switches
description: |
  'Summarizes uses of uncommon & undocumented commandline switches to create user accounts. User accounts may be created to achieve persistence on a machine.'
description-detailed: |
  'Summarizes uses of uncommon & undocumented commandline switches to create persistence
  User accounts may be created to achieve persistence on a machine.
  Read more here: https://attack.mitre.org/wiki/Technique/T1136
  Query for users being created using "net user" command
  "net user" commands are noisy, so needs to be joined with another signal -
  e.g. in this example we look for some undocumented variations (e.g. /ad instead of /add)'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - CredentialAccess
  - LateralMovement
relevantTechniques:
  - T1110
query: "```kusto\nSecurityEvent\n| where EventID==4688\n| project TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName, \n    AccountDomain=SubjectDomainName, FileName=tostring(split(NewProcessName, '\\\\')[-1]), \n    ProcessCommandLine = CommandLine, \n    FolderPath = \"\", InitiatingProcessFileName=ParentProcessName,\n    InitiatingProcessCommandLine=\"\",InitiatingProcessParentFileName=\"\"\n| where FileName in~ (\"net.exe\", \"net1.exe\")\n| parse kind=regex flags=iU ProcessCommandLine with * \"user \" CreatedUser \" \" * \"/ad\"\n| where not(FileName =~ \"net1.exe\" and InitiatingProcessFileName =~ \"net.exe\" and replace(\"net\", \"net1\", InitiatingProcessCommandLine) =~ ProcessCommandLine)\n| extend CreatedOnLocalMachine=(ProcessCommandLine !contains \"/do\")\n| where ProcessCommandLine contains \"/add\" or (CreatedOnLocalMachine == 0 and ProcessCommandLine !contains \"/domain\")\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), MachineCount=dcount(ComputerName) by CreatedUser, CreatedOnLocalMachine, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine\n| extend timestamp = StartTimeUtc, AccountCustomEntity = CreatedUser\n```"
version: 1.0.0
---

