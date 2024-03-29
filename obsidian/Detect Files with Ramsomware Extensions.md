---
id: 595aea5c-74c7-415b-8b12-10af1a338cdf
name: Detect Files with Ramsomware Extensions
description: |
  This hunting query identifies cretion of files with ransomware extensions. Ransomware file extensions are defined in a watchlist named RansomwareFileExtensions.
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
  - Execution
  - Impact
relevantTechniques:
  - T1204
  - T1486
query: |-
  ```kusto
  // Get list of ransomware file extensions from watchlist RansomwareFileExtension
  let RansomwareFileExtensions = _GetWatchlist('RansomwareFileExtensions') | where Enabled == 'Yes' | project FileExtension;
  _ASim_FileEvent
  | where EventType !in ('FileDeleted' , 'DeleteFile')
  | extend FileExtension =  tostring(split(FileName, '.')[1])
  | where FileExtension in~ (RansomwareFileExtensions)
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

