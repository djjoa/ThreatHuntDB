---
id: b43394b9-fa91-4d98-b331-619926a933bb
name: Detect New Scheduled Task Creation that Run Executables From Non-Standard Location
description: |
  This hunting query identifies new scheduled task created, to run executables from uncommon location like temp folders. Malware often creates scheduled tasks to execute malicious code and maintain persistence on a system.
tags:
  - Schema: _ASim_ProcessEvent
    SchemaVersion: 0.1.4
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
  - PrivilegeEscalation
  - Persistence
relevantTechniques:
  - T1053
query: |-
  ```kusto
  // List of file locations to monitor
  let fileLocations = dynamic([
      '\\Windows\\Temp\\',
      '\\AppData\\Local\\Temp\\',
      '\\Recycle Bin\\'
      ]);
  _ASim_ProcessEvent
  | where EventType == 'ProcessCreated'
  | where TargetProcessName has 'schtasks.exe' and TargetProcessCommandLine has_any (fileLocations)
  | project
      TimeGenerated,
      DvcHostname,
      DvcIpAddr,
      DvcDomain,
      TargetUsername,
      TargetUsernameType,
      TargetProcessName,
      TargetProcessId,
      CommandLine
  | extend Username = iff(tostring(TargetUsernameType) == 'Windows', tostring(split(TargetUsername, '\\')[1]), TargetUsername)
  | extend NTDomain = iff(tostring(TargetUsernameType) == 'Windows', tostring(split(TargetUsername, '\\')[0]), TargetUsername)
  | extend Username = iff(tostring(TargetUsernameType) == 'UPN', tostring(split(TargetUsername, '@')[0]), Username)
  | extend UPNSuffix = iff(tostring(TargetUsernameType) == 'UPN', tostring(split(TargetUsername, '@')[1]), '')
  | extend Host_0_HostName = DvcHostname
  | extend Host_0_DnsDomain = DvcDomain
  | extend Host_0_NTDomain = NTDomain
  | extend IP_0_Address = DvcIpAddr
  | extend Account_0_Name = Username
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend Account_0_NTDomain = NTDomain
  | extend Process_0_ProcessId = TargetProcessId
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
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DvcIpAddr
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Username
      - identifier: UPNSuffix
        columnName: UPNSuffix
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: TargetProcessId
      - identifier: CommandLine
        columnName: CommandLine
version: 1.0.0
---
