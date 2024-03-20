---
id: 54b222c4-0149-421e-9d6d-da66da50495a
name: Detect Modification to System Files or Directories by User Accounts
description: "This hunting query searches for modifications to system files or directories by a non system account (User Account). \n"
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
  - DefenseEvasion
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1036
  - T1543
query: "```kusto\n// List of system file and directories to monitor\nlet systemFilesAndDirs = dynamic([\n  \"\\\\Windows\\\\System32\", \n  \"//etc\", \n  \"//bin\", \n  \"//root\", \n  \"//lib\", \n  \"//usr\", \n  \"//dev\"\n]);\nlet systemUserTypes = dynamic([\n  'System',\n  'Service',\n  'Machine',\n  'Other'\n]);\n_ASim_FileEvent\n| where EventType in ('FileCreated' , 'FileModified')\n| where FilePath has_any (systemFilesAndDirs) and ActorUserType !in (systemUserTypes)\n| where isnotempty(ActorUserType)\n| project TimeGenerated, DvcHostname, DvcDomain, User, ActingProcessId, ActingProcessName, CommandLine, FileName, FilePath, Hash, HashType\n| summarize StartTime = max(TimeGenerated), EndTime = min(TimeGenerated) by DvcHostname, DvcDomain, User, ActingProcessId, ActingProcessName, CommandLine, FileName, FilePath, Hash, HashType\n| extend Username = iff(User contains '@', tostring(split(User, '@')[0]), User)\n| extend UPNSuffix = iff(User contains '@', tostring(split(User, '@')[1]), '')\n| extend Username = iff(User contains '\\\\', tostring(split(User, '\\\\')[1]), Username)\n| extend NTDomain = iff(User contains '\\\\', tostring(split(User, '\\\\')[0]), '')\n| extend Host_0_HostName = DvcHostname\n| extend Host_0_DnsDomain = DvcDomain\n| extend Host_0_NTDomain = NTDomain\n| extend Account_0_Name = Username\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Account_0_NTDomain = NTDomain\n| extend File_0_Name = FileName\n| extend File_0_Directory = FilePath\n| extend FileHash_0_Algorithm = HashType\n| extend FileHash_0_Value = Hash\n| extend Process_0_ProcessId = ActingProcessId\n| extend Process_0_CommandLine = CommandLine\n```"
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

