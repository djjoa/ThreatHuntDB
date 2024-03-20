---
id: 64e199a8-b26c-462f-a65c-09ed9b53a47b
name: Detect File Creation in Startup Folder
description: |
  This hunting query detects when a file is created in the Startup folder. This is a common technique used by adversaries to maintain persistence on a system.
tags:
  - Schema: _ASim_FileEvent
    SchemaVersion: 0.2.1
requiredDataConnectors:
  - connectorId: CrowdStrikeFalconEndpointProtection
    dataTypes:
      - CommonSecurityLog
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - SecurityAlert
  - connectorId: SentinelOne
    dataTypes:
      - SentinelOne_CL
  - connectorId: VMwareCarbonBlack
    dataTypes:
      - CarbonBlackEvents_CL
  - connectorId: CiscoSecureEndpoint
    dataTypes:
      - CiscoSecureEndpoint_CL
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - Persistence
  - PrivilegeEscalation
  - DefenseEvasion
relevantTechniques:
  - T1547
  - T1112
query: |-
  ```kusto
  // List of startup folders to monitor for Windows and Linux
  let startupFolderList = dynamic([
      '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\',
      '\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\',
      '/etc/init.d/',
      '/etc/rc.d/',
      '/etc/cron.d/'
    ]);
  _ASim_FileEvent
  | where EventType == 'FileCreated'
  | where FilePath has_any (startupFolderList)
  | project TimeGenerated, DvcHostname, DvcDomain, User, ActingProcessId, ActingProcessName, CommandLine, FileName, FilePath, Hash, HashType
  | extend Username = iff(User contains '@', tostring(split(User, '@')[0]), User)
  | extend UPNSuffix = iff(User contains '@', tostring(split(User, '@')[1]), '')
  | extend Username = iff(User contains '\\', tostring(split(User, '\\')[1]), Username)
  | extend NTDomain = iff(User contains '\\', tostring(split(User, '\\')[0]), '')
  | extend Host_0_HostName = DvcHostname
  | extend Host_0_DnsDomain = DvcDomain
  | extend Host_0_NTDomain = NTDomain
  | extend Account_0_Name = Username
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend Account_0_NTDomain = NTDomain
  | extend File_0_Name = FileName
  | extend File_0_Directory = FilePath
  | extend FileHash_0_Algorithm = HashType
  | extend FileHash_0_Value = Hash
  | extend Process_0_ProcessId = ActingProcessId
  | extend Process_0_CommandLine = CommandLine
  ```
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DvcHostname
      - identifier: DnsDomain
        columnName: DvcDomain
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Username
      - identifier: UPNSuffix
        columnName: UPNSuffix
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileName
      - identifier: Directory
        columnName: FilePath
  - entityType: FileHash
    fieldMappings:
      - identifier: Algorithm
        columnName: HashType
      - identifier: Value
        columnName: Hash
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: ActingProcessId
      - identifier: CommandLine
        columnName: CommandLine
version: 1.0.0
---
