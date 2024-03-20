---
id: bb30abbc-9af6-4a37-9536-e9207e023989
name: Nylon Typhoon Command Line Activity November 2021
description: |
  'This query hunts for Nylon Typhoon-related activity, specifically data collection and staging. It looks for use of tools like xcopy and renamed archiving tools on hosts with observed signatures.'
description-detailed: |
  'This hunting query looks for process command line activity related to data collection and staging observed by Nylon Typhoon.
  It hunts for use of tools such as xcopy and renamed archiving tools for data collection and staging purposes on the hosts with signatures observed related to Nylon Typhoon actor.'
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
  - Collection
relevantTechniques:
  - T1074.001
query: "```kusto\nlet xcopy_tokens = dynamic([\"xcopy\", \"\\\\windows\\\\temp\\\\wmi\", \"/S/Y/C\"]);\nlet archive_tokens = dynamic([\"\\\\windows\\\\temp\\\\wmi\", \".rar\", \".7zip\"]);\nlet SigNames = dynamic([\"Backdoor:Win32/Leeson\", \"Trojan:Win32/Kechang\", \"Backdoor:Win32/Nightimp!dha\", \"Trojan:Win32/QuarkBandit.A!dha\", \"TrojanSpy:Win32/KeyLogger\"]);\n(union isfuzzy=true\n(DeviceProcessEvents  \n| where ProcessCommandLine has_all(xcopy_tokens) or (ProcessCommandLine has_all (archive_tokens)) \n| join kind=leftouter (\nSecurityAlert\n| where ProductName == \"Microsoft Defender Advanced Threat Protection\"\n| extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)\n| where isnotempty(ThreatName)\n| extend AlertRiskScore =iif(ThreatName has_any (SigNames), 1.0, 0.5))\n| extend AlertRiskScore = iif(isempty(AlertRiskScore), 0.0 , AlertRiskScore)\n| project-reorder  TimeGenerated, DeviceName, DeviceId, ProcessCommandLine, AccountName\n| extend timestamp = TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName,  ProcessCustomEntity = InitiatingProcessFileName\n),\n(imProcessCreate\n| where (CommandLine has_all (xcopy_tokens)) or (CommandLine has_all (archive_tokens))\n| extend timestamp = TimeGenerated, HostCustomEntity = DvcHostname , AccountCustomEntity = ActorUsername, ProcessCustomEntity = TargetProcessName\n),\n(SecurityEvent\n| where EventID == '4688'\n| where (CommandLine has_all (xcopy_tokens)) or (CommandLine has_all (archive_tokens))\n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n),\n(WindowsEvent\n| where EventID == '4688' and (EventData has_all (xcopy_tokens) or EventData has_all (archive_tokens))\n| extend CommandLine = tostring(EventData.CommandLine) \n| where (CommandLine has_all (xcopy_tokens)) or (CommandLine has_all (archive_tokens))\n| extend NewProcessName = tostring(EventData.NewProcessName)\n| extend ParentProcessName = tostring(EventData.ParentProcessName)\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| extend NewProcessId = tostring(EventData.NewProcessId)\n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n)\n)\n| extend NTDomain = tostring(split(AccountCustomEntity, '\\\\', 0)[0]), Name = tostring(split(AccountCustomEntity, '\\\\', 1)[0])\n| extend HostName = tostring(split(HostCustomEntity, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(HostCustomEntity, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend Process_0_ProcessId = ProcessCustomEntity\n| extend Process_0_CommandLine = CommandLineCustomEntity\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
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
      - identifier: CommandLine
        columnName: CommandLineCustomEntity
version: 1.0.1
---

