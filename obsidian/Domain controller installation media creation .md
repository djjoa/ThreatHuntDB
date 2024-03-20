---
id: 7e5f3a9a-542c-417a-a429-4ed500c5c4d8
name: Domain controller installation media creation
description: |
  'This hunting query helps to detect attempts to create installation media from domain controllers, either remotely or locally using a commandline tool called ntdsutil. These media are intended to be used in the installation of new domain controllers.'
requiredDataConnectors:
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - CredentialAccess
relevantTechniques:
  - T1003
tags:
  - VoltTyphoon
query: "```kusto\n(union isfuzzy=true \n(SecurityEvent\n| where EventID == 4688\n| where CommandLine has_all (\"ntdsutil\", \"ac i ntds\", \"create full\")\n| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SourceComputerId, SubjectLogonId, SubjectUserSid\n),\n(WindowsEvent\n| where EventID == 4688 \n| extend CommandLine = tostring(EventData.CommandLine)\n| where CommandLine has_all (\"ntdsutil\", \"ac i ntds\", \"create full\")\n| extend NewProcessName = tostring(EventData.NewProcessName), NewProcessId = tostring(EventData.NewProcessId)\n| extend Process=tostring(split(NewProcessName, '\\\\')[-1]),  ProcessId = tostring(EventData.ProcessId)\n| extend Account =  strcat(EventData.SubjectDomainName,\"\\\\\", EventData.SubjectUserName)\n| extend ParentProcessName = tostring(EventData.ParentProcessName) \n| extend SubjectUserName = tostring(EventData.SubjectUserName), SubjectDomainName = tostring(EventData.SubjectDomainName), SubjectLogonId = tostring(EventData.SubjectLogonId)\n| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SubjectUserName, SubjectDomainName, SubjectLogonId\n) \n)\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: Account
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: Process
version: 1.0.1
---

