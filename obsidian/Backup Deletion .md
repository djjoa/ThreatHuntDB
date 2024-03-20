---
id: 56ebae61-89cf-42d9-99f4-3dff8ba33885
name: Backup Deletion
description: |
  'This hunting query helps to detect attempts to delete backup. Though such an activity could be legitimate as part of regular business operations, often ransomware also perform such actions so that once the files are encrypted by them, backups cannot be used to restore encrypted files and thus causing interruption to regular business services.'
requiredDataConnectors:
  - connectorId: MicrosoftDefenderAdvancedThreatProtection
    dataTypes:
      - SecurityAlert (MDATP)
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - Impact
relevantTechniques:
  - T1490
tags:
  - HiveRansomware
  - Schema: ASIMProcessEvent
    SchemaVersion: 0.1.0
query: "```kusto\n( union isfuzzy=true\n(SecurityEvent\n| where EventID==4688\n| extend FileName = Process, ProcessCommandLine = CommandLine\n| where FileName =~ \"vssadmin.exe\" and ProcessCommandLine has \"delete shadows\"\n or ProcessCommandLine has(\"bcdedit\") and ProcessCommandLine has_any(\"recoveryenabled no\", \"bootstatuspolicy ignoreallfailures\")\n or (ProcessCommandLine has \"wmic\" and ProcessCommandLine has \"shadowcopy delete\")\n or ProcessCommandLine has \"wbadmin\" and ProcessCommandLine has \"delete\" and ProcessCommandLine has_any(\"backup\", \"catalog\", \"systemstatebackup\")\n| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = Computer, ProcessCustomEntity = NewProcessName\n),\n(WindowsEvent\n| where EventID == 4688 \n| extend ProcessCommandLine = tostring(EventData.CommandLine)\n| where  EventData has \"vssadmin.exe\" and ProcessCommandLine has \"delete shadows\"\n or ProcessCommandLine has(\"bcdedit\") and ProcessCommandLine has_any(\"recoveryenabled no\", \"bootstatuspolicy ignoreallfailures\")\n or (ProcessCommandLine has \"wmic\" and ProcessCommandLine has \"shadowcopy delete\")\n or ProcessCommandLine has \"wbadmin\" and ProcessCommandLine has \"delete\" and ProcessCommandLine has_any(\"backup\", \"catalog\", \"systemstatebackup\") \n| extend Account = strcat(EventData.TargetDomainName,\"\\\\\", EventData.TargetUserName)\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = Account, ProcessCustomEntity = tostring(EventData.NewProcessName)\n),\n(DeviceProcessEvents\n| where FileName =~ \"vssadmin.exe\" and ProcessCommandLine has \"delete shadows\"\n or ProcessCommandLine has(\"bcdedit\") and ProcessCommandLine has_any(\"recoveryenabled no\", \"bootstatuspolicy ignoreallfailures\")\n or (ProcessCommandLine has \"wmic\" and ProcessCommandLine has \"shadowcopy delete\")\n or ProcessCommandLine has \"wbadmin\" and ProcessCommandLine has \"delete\" and ProcessCommandLine has_any(\"backup\", \"catalog\", \"systemstatebackup\")\n| extend Account = strcat(AccountDomain,\"\\\\\", AccountName)\n| extend timestamp = TimeGenerated, AccountCustomEntity = Account, HostCustomEntity = DeviceName, ProcessCustomEntity = InitiatingProcessFileName\n),\n(imProcessCreate\n| extend FileName = Process, ProcessCommandLine = CommandLine\n| where FileName =~ \"vssadmin.exe\" and ProcessCommandLine has \"delete shadows\"\n or ProcessCommandLine has(\"bcdedit\") and ProcessCommandLine has_any(\"recoveryenabled no\", \"bootstatuspolicy ignoreallfailures\")\n or (ProcessCommandLine has \"wmic\" and ProcessCommandLine has \"shadowcopy delete\")\n or ProcessCommandLine has \"wbadmin\" and ProcessCommandLine has \"delete\" and ProcessCommandLine has_any(\"backup\", \"catalog\", \"systemstatebackup\")\n| extend timestamp = TimeGenerated, AccountCustomEntity = ActorUsername, HostCustomEntity = Dvc, ProcessCustomEntity = Process\n)\n)\n| extend NTDomain = tostring(split(AccountCustomEntity, '\\\\', 0)[0]), UserName = tostring(split(AccountCustomEntity, '\\\\', 1)[0])\n| extend HostName = tostring(split(HostCustomEntity, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(HostCustomEntity, '.'), 1, -1), '.'))\n| extend Account_0_Name = UserName\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend Process_0_ProcessId = ProcessCustomEntity\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: ProcessCustomEntity
version: 1.1.0
---

