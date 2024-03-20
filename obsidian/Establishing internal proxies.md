---
id: ce38c16c-a560-46c0-88d6-7757b88f08e9
name: Establishing internal proxies
description: "'This hunting query helps to detect attempts to create proxies on compromised systems using the \n built-in netsh portproxy command. VoltTyphoon has been seen creating these proxies on compromised hosts to manage command and control communications.'\n"
requiredDataConnectors:
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - CommandandControl
relevantTechniques:
  - T1090
tags:
  - VoltTyphoon
query: "```kusto\n(union isfuzzy=true \n(SecurityEvent\n| where EventID == 4688\n| where CommandLine has_all (\"portproxy\", \"netsh\", \"wmic\", \"process call create\", \"v4tov4\", \"listenport=50100\")\n| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SourceComputerId, SubjectLogonId, SubjectUserSid\n),\n(WindowsEvent\n| where EventID == 4688 \n| extend CommandLine = tostring(EventData.CommandLine)\n| where CommandLine has_all (\"portproxy\", \"netsh\", \"wmic\", \"process call create\", \"v4tov4\", \"listenport=50100\")\n| extend NewProcessName = tostring(EventData.NewProcessName), NewProcessId = tostring(EventData.NewProcessId)\n| extend Process=tostring(split(NewProcessName, '\\\\')[-1]),  ProcessId = tostring(EventData.ProcessId)\n| extend Account =  strcat(EventData.SubjectDomainName,\"\\\\\", EventData.SubjectUserName)\n| extend ParentProcessName = tostring(EventData.ParentProcessName) \n| extend SubjectUserName = tostring(EventData.SubjectUserName), SubjectDomainName = tostring(EventData.SubjectDomainName), SubjectLogonId = tostring(EventData.SubjectLogonId)\n| project TimeGenerated, Computer, Account, Process, ProcessId, NewProcessName, NewProcessId, CommandLine, ParentProcessName, _ResourceId, SubjectUserName, SubjectDomainName, SubjectLogonId\n) \n)\n```"
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
version: 1.0.0
---

