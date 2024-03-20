---
id: 6b652b4f-9810-4eec-9027-7aa88ce4db23
name: Dev-0270 WMIC  Discovery
description: |
  'The query below identifies dllhost.exe using WMIC to discover additional hosts and associated domains in the environment.'
severity: High
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
queryFrequency: 6h
queryPeriod: 6h
triggerOperator: gt
triggerThreshold: 0
status: Available
tactics:
  - Discovery
relevantTechniques:
  - T1482
tags:
  - Dev-0270
query: "```kusto\n(union isfuzzy=true\n(SecurityEvent\n| where EventID==4688\n| where CommandLine has \"wmic computersystem get domain\" and ParentProcessName has \"dllhost.exe\"\n| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type\n),\n(DeviceProcessEvents \n| where ProcessCommandLine has \"wmic computersystem get domain\" and InitiatingProcessFileName =~ \"dllhost.exe\" and InitiatingProcessCommandLine has \"dllhost.exe\"\n| extend timestamp = TimeGenerated, AccountCustomEntity =  InitiatingProcessAccountName, HostCustomEntity = DeviceName\n)\n)\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
version: 1.0.2
kind: Scheduled
---

