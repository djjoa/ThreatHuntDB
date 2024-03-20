---
id: 2d1a3e86-f1a0-49d0-b88a-55789e1d6660
name: Possible command injection attempts against Azure Integration Runtimes
description: "'This hunting query looks for potential command injection attempts via the vulnerable third-party driver against Azure IR with Managed VNet or SHIR processes as well as post-exploitation activity based on process execution and command line activity\nReference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-29972 \n https://msrc-blog.microsoft.com/2022/05/09/vulnerability-mitigated-in-the-third-party-data-connector-used-in-azure-synapse-pipelines-and-azure-data-factory-cve-2022-29972'\n"
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
query: "```kusto\nlet parent_proc_list = dynamic([\"diawp.exe\", \"ReportingServicesService.exe\", \"RSPortal.exe\", \"RsPowerBI.exe\", \"taskexecutor.exe\"]);\nlet cmdline_tokens = dynamic([\"| curl \", \"/c start \", \" whoami 2>&1\", \"-m 5 \", \"--data-binary\"]);\n(union isfuzzy=true\n( DeviceProcessEvents  \n| where FileName =~ \"cmd.exe\"\n| where InitiatingProcessFileName in~ (parent_proc_list)\n| where ProcessCommandLine has_any (cmdline_tokens)\n| project-reorder  TimeGenerated, DeviceName, DeviceId, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName\n| extend timestamp = TimeGenerated, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName,  ProcessCustomEntity = FileName\n),\n(imProcessCreate\n| where ParentProcessName endswith \"diawp.exe\" or ParentProcessName endswith \"ReportingServicesService.exe\" or ParentProcessName endswith \"RSPortal.exe\" or ParentProcessName endswith \"RsPowerBI.exe\" or ParentProcessName endswith \"taskexecutor.exe\"\n| where ActingProcessName == \"cmd.exe\"\n| where (CommandLine has_any (cmdline_tokens))\n| extend timestamp = TimeGenerated, HostCustomEntity = DvcHostname , AccountCustomEntity = ActorUsername, ProcessCustomEntity = TargetProcessName\n),\n(SecurityEvent\n| where EventID == '4688'\n| where Process == \"cmd.exe\" and isnotempty(ParentProcessName)\n| extend ParentProcess = tostring(parse_json(parse_path(ParentProcessName)).Filename)\n| where ParentProcess in~ (parent_proc_list)  and (CommandLine has_any (cmdline_tokens)) \n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n),\n(WindowsEvent\n| where EventID == '4688' and (EventData has_any (cmdline_tokens) or EventData has_all (parent_proc_list))\n| extend CommandLine = tostring(EventData.CommandLine) \n| extend NewProcessName = tostring(EventData.NewProcessName)\n| extend ParentProcessName = tostring(EventData.ParentProcessName)\n| where NewProcessName =~ \"cmd.exe\" and ParentProcessName in~ (parent_proc_list)\n| where (CommandLine has_any (cmdline_tokens))\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| extend NewProcessId = tostring(EventData.NewProcessId)\n| project TimeGenerated, Computer, NewProcessName, ParentProcessName, Account, NewProcessId, Type, CommandLine\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer , AccountCustomEntity = Account, ProcessCustomEntity = NewProcessName\n)\n)\n| extend NTDomain = tostring(split(AccountCustomEntity, '\\\\', 0)[0]), Name = tostring(split(AccountCustomEntity, '\\\\', 1)[0])\n| extend HostName = tostring(split(HostCustomEntity, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(HostCustomEntity, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend Process_0_ProcessId = ProcessCustomEntity\n| extend Process_0_CommandLine = CommandLineCustomEntity\n```"
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

