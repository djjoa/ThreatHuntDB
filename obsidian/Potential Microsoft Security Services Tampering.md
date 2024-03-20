---
id: e10e1d2f-265d-4d90-9037-7f3a6ed8a91e
name: Potential Microsoft Security Services Tampering
description: |
  'This query identifies potential tampering related to Microsoft security related products and services.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvents
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1562.001
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nlet includeProc = dynamic([\"sc.exe\",\"net1.exe\",\"net.exe\", \"taskkill.exe\", \"cmd.exe\", \"powershell.exe\"]);\nlet action = dynamic([\"stop\",\"disable\", \"delete\"]);\nlet service1 = dynamic(['sense', 'windefend', 'mssecflt']);\nlet service2 = dynamic(['sense', 'windefend', 'mssecflt', 'healthservice']);\nlet params1 = dynamic([\"-DisableRealtimeMonitoring\", \"-DisableBehaviorMonitoring\" ,\"-DisableIOAVProtection\"]);\nlet params2 = dynamic([\"sgrmbroker.exe\", \"mssense.exe\"]);\nlet regparams1 = dynamic(['reg add \"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender\"', 'reg add \"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Advanced Threat Protection\"']);\nlet regparams2 = dynamic(['ForceDefenderPassiveMode', 'DisableAntiSpyware']);\nlet regparams3 = dynamic(['sense', 'windefend']);\nlet regparams4 = dynamic(['demand', 'disabled']);\nlet regparams5 = dynamic(['reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\services\\\\HealthService\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\Sense\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinDefend\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\MsSecFlt\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\DiagTrack\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\SgrmBroker\"', 'reg add \"HKLMSYSTEM\\\\CurrentControlSet\\\\Services\\\\SgrmAgent\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\AATPSensorUpdater\"' , 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\AATPSensor\"', 'reg add \"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\mpssvc\"']);\nlet regparams6 = dynamic(['/d 4','/d \"4\"','/d 0x00000004']);\nlet regparams7 = dynamic(['/d 1','/d \"1\"','/d 0x00000001']);\n(union isfuzzy=true\n(\nSecurityEvent\n| where EventID == 4688\n| extend ProcessName = tostring(split(NewProcessName, '\\\\')[-1])\n| where ProcessName in~ (includeProc)\n| where (CommandLine has_any (action) and CommandLine has_any (service1)) \nor (CommandLine has_any (params1) and CommandLine has 'Set-MpPreference' and CommandLine has '$true')\nor (CommandLine has_any (params2) and CommandLine has \"/IM\") \nor (CommandLine has_any (regparams5) and CommandLine has 'Start' and CommandLine has_any (regparams6))\nor (CommandLine has_any (regparams1) and CommandLine has_any (regparams2) and CommandLine has_any (regparams7)) \nor (CommandLine has \"start\" and CommandLine has \"config\" and CommandLine has_any (regparams3) and CommandLine has_any (regparams4))\n| project TimeGenerated, Computer, Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type\n),\n(\nWindowsEvent\n| where EventID == 4688 and EventData has_any(includeProc)\n| where (EventData  has_any (action) and EventData has_any (service1)) \nor (EventData has_any (params1) and EventData has 'Set-MpPreference' and EventData has '$true')\nor (EventData has_any (params2) and EventData has \"/IM\") \nor (EventData has_any (regparams5) and EventData has 'Start' and EventData has_any (regparams6))\nor (EventData has_any (regparams1) and EventData has_any (regparams2) and EventData has_any (regparams7)) \nor (EventData has \"start\" and EventData has \"config\" and EventData has_any (regparams3) and EventData has_any (regparams4))\n| extend NewProcessName = tostring(EventData.NewProcessName)\n| extend ProcessName = tostring(split(NewProcessName, '\\\\')[-1])\n| where ProcessName in~ (includeProc)\n| extend CommandLine = tostring(EventData.CommandLine) \n| where (CommandLine has_any (action) and CommandLine has_any (service1)) \nor (CommandLine has_any (params1) and CommandLine has 'Set-MpPreference' and CommandLine has '$true')\nor (CommandLine has_any (params2) and CommandLine has \"/IM\") \nor (CommandLine has_any (regparams5) and CommandLine has 'Start' and CommandLine has_any (regparams6))\nor (CommandLine has_any (regparams1) and CommandLine has_any (regparams2) and CommandLine has_any (regparams7)) \nor (CommandLine has \"start\" and CommandLine has \"config\" and CommandLine has_any (regparams3) and CommandLine has_any (regparams4))\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| extend AccountDomain = tostring(EventData.AccountDomain)\n| extend Activity=\"4688 - A new process has been created.\"\n| extend EventSourceName=Provider\n| project TimeGenerated, Computer, Account, AccountDomain, ProcessName, ProcessNameFullPath = NewProcessName, EventID, Activity, CommandLine, EventSourceName, Type\n),\n(\nEvent\n| where Source =~ \"Microsoft-Windows-SENSE\"\n| where EventID == 87 and ParameterXml in (\"<Param>sgrmbroker</Param>\", \"<Param>WinDefend</Param>\")\n| project TimeGenerated, Computer, Account = UserName, EventID, Activity = RenderedDescription, EventSourceName = Source, Type\n),\n(\nDeviceProcessEvents\n| where InitiatingProcessFileName in~ (includeProc)\n| where (InitiatingProcessCommandLine has_any(action) and InitiatingProcessCommandLine has_any (service2) and InitiatingProcessParentFileName != 'cscript.exe')\nor (InitiatingProcessCommandLine has_any (params1) and InitiatingProcessCommandLine has 'Set-MpPreference' and InitiatingProcessCommandLine has '$true') \nor (InitiatingProcessCommandLine has_any (params2) and InitiatingProcessCommandLine has \"/IM\") \nor ( InitiatingProcessCommandLine has_any (regparams5) and  InitiatingProcessCommandLine has 'Start' and  InitiatingProcessCommandLine has_any (regparams6))\nor (InitiatingProcessCommandLine has_any (regparams1) and InitiatingProcessCommandLine has_any (regparams2) and InitiatingProcessCommandLine has_any (regparams7)) \nor (InitiatingProcessCommandLine has_any(\"start\") and InitiatingProcessCommandLine has \"config\" and InitiatingProcessCommandLine has_any (regparams3) and InitiatingProcessCommandLine has_any (regparams4))\n| extend Account = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), Computer = DeviceName\n| project TimeGenerated, Computer, Account, AccountDomain, ProcessName = InitiatingProcessFileName, ProcessNameFullPath = FolderPath, Activity = ActionType, CommandLine = InitiatingProcessCommandLine, Type, InitiatingProcessParentFileName\n)\n)\n| extend timestamp = TimeGenerated\n| extend NTDomain = tostring(split(Account, '\\\\', 0)[0]), UserName = tostring(split(Account, '\\\\', 1)[0])\n| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n| extend Account_0_Name = UserName\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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
version: 1.0.1
---

