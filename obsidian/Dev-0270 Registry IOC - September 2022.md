---
id: 2566e99f-ad0f-472a-b9ac-d3899c9283e6
name: Dev-0270 Registry IOC - September 2022
description: |
  'The query below identifies modification of registry by Dev-0270 actor to disable security feature as well as to add ransom notes'
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
  - Impact
relevantTechniques:
  - T1486
tags:
  - Dev-0270
query: "```kusto\n(union isfuzzy=true\n(SecurityEvent\n| where EventID == 4688\n| where (CommandLine has_all  ('reg', 'add', 'HKLM\\\\SOFTWARE\\\\Policies\\\\', '/v','/t', 'REG_DWORD', '/d', '/f') and CommandLine has_any('DisableRealtimeMonitoring', 'UseTPMKey', 'UseTPMKeyPIN', 'UseAdvancedStartup', 'EnableBDEWithNoTPM', 'RecoveryKeyMessageSource'))\n  or CommandLine has_all ('reg', 'add', 'HKLM\\\\SOFTWARE\\\\Policies\\\\', '/v','/t', 'REG_DWORD', '/d', '/f', 'RecoveryKeyMessage', 'Your drives are Encrypted!', '@')\n| project TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type\n),\n(DeviceProcessEvents \n| where (InitiatingProcessCommandLine has_all(@'\"reg\"', 'add', @'\"HKLM\\SOFTWARE\\Policies\\', '/v','/t', 'REG_DWORD', '/d', '/f') \n   and InitiatingProcessCommandLine has_any('DisableRealtimeMonitoring', 'UseTPMKey', 'UseTPMKeyPIN', 'UseAdvancedStartup', 'EnableBDEWithNoTPM', 'RecoveryKeyMessageSource') ) \n   or InitiatingProcessCommandLine has_all('\"reg\"', 'add', @'\"HKLM\\SOFTWARE\\Policies\\', '/v','/t', 'REG_DWORD', '/d', '/f', 'RecoveryKeyMessage', 'Your drives are Encrypted!', '@')\n| extend timestamp = TimeGenerated, AccountCustomEntity =  InitiatingProcessAccountName, HostCustomEntity = DeviceName\n )\n )\n```"
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

