---
id: ab8ddb26-050c-40aa-aaf0-bfb7e3eeb05f
name: Executable Files Created in Uncommon Locations
description: |
  This analytic rule detects any executable file creation in uncommon locations like temproray folders. This could be an indication of a persistence or defese evasion attempt by an adversary.
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
  - T1037
  - T1547
  - T1564
query: |-
  ```kusto
  // List of file extensions to monitor
  let executableExtensions = dynamic(['exe', 'bat', 'cmd', 'vbs', 'ps1', 'psm1', 'wsf']);
  // List of file locations to monitor
  let fileLocations = dynamic([
      '\\Windows\\System32\\',
      '\\Windows\\Temp\\',
      '\\AppData\\Local\\Temp\\',
      '\\Recycle Bin\\'
      ]);
  _ASim_FileEvent
  | where EventType == 'FileCreated'
  | extend FileExtension =  tostring(split(FileName, '.')[1])
  | where FileExtension in~ (executableExtensions) and FilePath has_any (fileLocations)
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

