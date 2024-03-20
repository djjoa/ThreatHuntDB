---
id: e2629949-2043-4421-8064-bca23c8491dd
name: Dev-0056 Command Line Activity November 2021
description: |
  'This hunting query looks for process command line activity related to activity observed by Dev-0056.The command lines this query hunts for are used as part of the threat actor's post exploitation activity.'
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
  - CommandAndControl
relevantTechniques:
  - T1071
query: "```kusto\n(union isfuzzy=true\n(DeviceProcessEvents  \n| where ProcessCommandLine has_any(\"/q /c color f7&\", \"Net.We$()bClient\", \"$b,15,$b.Length-15\") or (ProcessCommandLine has \"FromBase64String\" and ProcessCommandLine has_all(\"-nop\", \"iex\", \"(iex\")) \n| join kind=leftouter (SecurityAlert\n| where ProviderName =~ \"MDATP\"\n| extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)\n| mv-expand todynamic(Entities)\n| extend DeviceId = tostring(parse_json(Entities).MdatpDeviceId)\n| where isnotempty(DeviceId)\n// Increase risk score further if alerts relate to malware assocaited with threat actor\n| extend AlertRiskScore =iif(ThreatName has_any (\"Backdoor:MSIL/ShellClient.A\", \"Backdoor:MSIL/ShellClient.A!dll\", \"Trojan:MSIL/Mimikatz.BA!MTB\"), 1.0, 0.5)) on DeviceId\n| extend AlertRiskScore = iif(isempty(AlertRiskScore), 0.0 , AlertRiskScore)\n| project-reorder  TimeGenerated, DeviceName, DeviceId, ProcessCommandLine, AccountName\n| extend timestamp = TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName,  ProcessCustomEntity = InitiatingProcessFileName\n),\n(SecurityEvent\n| where EventID == '4688'\n| where ( CommandLine has_any(\"/q /c color f7&\", \"Net.We$()bClient\", \"$b,15,$b.Length-15\")) or (CommandLine has \"FromBase64String\" and CommandLine has_all(\"-nop\", \"iex\", \"(iex\"))\n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n),\n(WindowsEvent\n| where EventID == '4688' and (EventData has_any(\"/q /c color f7&\", \"Net.We$()bClient\", \"$b,15,$b.Length-15\") or (EventData has \"FromBase64String\" and EventData has_all(\"-nop\", \"iex\", \"(iex\")) )\n| extend CommandLine = tostring(EventData.CommandLine) \n| where ( CommandLine has_any(\"/q /c color f7&\", \"Net.We$()bClient\", \"$b,15,$b.Length-15\")) or (CommandLine has \"FromBase64String\" and CommandLine has_all(\"-nop\", \"iex\", \"(iex\"))\n| extend NewProcessName = tostring(EventData.NewProcessName)\n| extend ParentProcessName = tostring(EventData.ParentProcessName)\n| extend Account = iff((isempty(EventData.SubjectDomainName) or EventData.SubjectDomainName == \"-\"),\"\", strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName)))\n| extend NewProcessId = tostring(EventData.NewProcessId)\n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n)\n)\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
  - entityType: Process
    fieldMappings:
      - identifier: ProcessId
        columnName: ProcessCustomEntity
---

