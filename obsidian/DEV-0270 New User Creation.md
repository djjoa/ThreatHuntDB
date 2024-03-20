---
id: 7965f0be-c039-4d18-8ee8-9a6add8aecf3
name: DEV-0270 New User Creation
description: |
  'The following query tries to detect creation of a new user using a known DEV-0270 username/password schema'
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
  - Persistence
relevantTechniques:
  - T1098
tags:
  - Dev-0270
query: "```kusto\n(union isfuzzy=true\n(SecurityEvent\n| where EventID == 4688\n| where CommandLine has_all ('net user', '/add') \n| parse CommandLine with * \"user \" username \" \"*\n| extend password = extract(@\"\\buser\\s+[^\\s]+\\s+([^\\s]+)\", 1, CommandLine) \n| where username in('DefaultAccount') or password in('P@ssw0rd1234', '_AS_@1394') \n| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type\n),\n(DeviceProcessEvents \n| where InitiatingProcessCommandLine has_all('net user', '/add') \n| parse InitiatingProcessCommandLine with * \"user \" username \" \"* \n| extend password = extract(@\"\\buser\\s+[^\\s]+\\s+([^\\s]+)\", 1, InitiatingProcessCommandLine) \n| where username in('DefaultAccount') or password in('P@ssw0rd1234', '_AS_@1394') \n| extend timestamp = TimeGenerated, AccountCustomEntity =  InitiatingProcessAccountName, HostCustomEntity = DeviceName\n)\n)\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
version: 1.0.1
kind: Scheduled
---

