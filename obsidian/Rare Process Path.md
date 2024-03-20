---
id: 0ff22697-dc58-4623-b844-a767629840cd
name: Rare Process Path
description: |
  'Identifies when a process is running from a rare path. This could indicate malicious or unexpected activity as attacks
  often try to use common process names running from non-standard locations'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = totimespan((endtime-starttime)*7);\nlet processEvents=\nSecurityEvent\n| where TimeGenerated between(ago(lookback)..endtime)\n| where EventID==4688\n// excluding well known processes\n| where NewProcessName !endswith ':\\\\Windows\\\\System32\\\\conhost.exe' and ParentProcessName !endswith ':\\\\Windows\\\\System32\\\\conhost.exe'\n| where ParentProcessName !endswith \":\\\\Windows\\\\System32\\\\wuauclt.exe\" and NewProcessName !startswith \"C:\\\\Windows\\\\SoftwareDistribution\\\\Download\\\\Install\\\\AM_Delta_Patch_\"\n| where NewProcessName !has \":\\\\Windows\\\\WinSxS\\\\amd64_microsoft-windows-servicingstack_\" and ParentProcessName !has \":\\\\Windows\\\\WinSxS\\\\amd64_microsoft-windows-servicingstack_\"\n| where NewProcessName !endswith \":\\\\WindowsAzure\\\\SecAgent\\\\WaSecAgentProv.exe\"\n| where ParentProcessName !has \":\\\\WindowsAzure\\\\GuestAgent_\" and NewProcessName !has \":\\\\WindowsAzure\\\\GuestAgent_\"\n| where ParentProcessName !has \":\\\\WindowsAzure\\\\WindowsAzureNetAgent_\" and NewProcessName !has \":\\\\WindowsAzure\\\\WindowsAzureNetAgent_\"\n| where ParentProcessName !has \":\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\platform\\\\\" and ParentProcessName !endswith \"\\\\MpCmdRun.exe\"\n| where NewProcessName !has \":\\\\ProgramData\\\\Microsoft\\\\Windows Defender\\\\platform\\\\\" and NewProcessName !endswith \"\\\\MpCmdRun.exe\"\n| where NewProcessName !has ':\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\'\n// filter out common randomly named paths and files\n| where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{3}\\.tmp\")\n| where not(NewProcessName matches regex @\"\\\\TRA[0-9A-Fa-f]{4}\\.tmp\")\n| where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{3}\\.tmp\")\n| where not(NewProcessName matches regex @\"Installer\\\\MSI[0-9A-Fa-f]{4}\\.tmp\")\n| where not(NewProcessName matches regex @\"\\\\Windows\\\\Temp\\\\[0-9A-Za-z-]*\\\\DismHost\\.exe\")\n| where not(NewProcessName matches regex @\"\\\\Users\\\\[0-9A-Za-z-_~\\.]*\\\\AppData\\\\Local\\\\Temp\\\\[0-9A-Za-z-]*\\\\DismHost\\.exe\")\n| where not(NewProcessName matches regex @\"\\\\Windows\\\\Temp\\\\[0-9A-Za-z-]*\\\\MpSigStub\\.exe\")\n| where not(NewProcessName matches regex @\"\\\\[0-9A-Za-z]*\\\\amd64\\\\setup\\.exe\") and (ParentProcessName !has \":\\\\Windows\\\\SoftwareDistribution\\\\Download\\\\Install\\\\\"\nor ParentProcessName !has \"\\\\AppData\\\\Local\\\\Temp\\\\mpam-\")\n| where not(NewProcessName matches regex @\"\\\\Windows\\\\Microsoft.NET\\\\(Framework|Framework64)\\\\v[0-9].[0-9].[0-9]*\\\\(csc\\.exe|cvtres\\.exe|mscorsvw\\.exe|ngentask\\.exe|ngen\\.exe)\")\n| where not(NewProcessName matches regex @\"\\\\WindowsAzure\\\\GuestAgent_[0-9].[0-9].[0-9]*.[0-9]*_[0-9]*-[0-9]*-[0-9]*_[0-9]*\\\\\")\nand not(ParentProcessName matches regex @\"\\\\WindowsAzure\\\\GuestAgent_[0-9].[0-9].[0-9]*.[0-9]*_[0-9]*-[0-9]*-[0-9]*_[0-9]*\\\\\")\n| where not(NewProcessName matches regex @\"\\\\[0-9A-Za-z]*\\\\epplauncher.exe\")\n| where not(NewProcessName matches regex @\"\\\\Packages\\\\Plugins\\\\Microsoft\\.\")\n| extend path_parts = parse_path(NewProcessName)\n| extend ProcessPath = tostring(path_parts.DirectoryPath)\n;\nlet normalizedProcessPath = processEvents\n| extend NormalizedProcessPath = ProcessPath\n// normalize guids\n| project TimeGenerated, Computer, Account, Process, ProcessPath,\nNormalizedProcessPath = replace(\"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}\", \"<guid>\", NormalizedProcessPath)\n// normalize digits away\n| project TimeGenerated, Computer, Account, Process, ProcessPath, NormalizedProcessPath = replace(@'\\d', '#', NormalizedProcessPath)\n;\nlet freqs = normalizedProcessPath\n| summarize make_list(Computer, 1000), make_list(Account, 1000), make_list(ProcessPath, 1000), frequency=count() by NormalizedProcessPath, Process\n| join kind= leftouter (\nnormalizedProcessPath\n| summarize StartTimeUtc=min(TimeGenerated), EndTimeUtc=max(TimeGenerated) by NormalizedProcessPath, Process\n) on NormalizedProcessPath, Process;\nfreqs\n| where frequency <= toscalar( freqs | serialize | project frequency | summarize percentiles(frequency, 5))\n| order by frequency asc\n| mv-expand Computer = list_Computer, Account = list_Account, ProcessPath = list_ProcessPath\n| project StartTimeUtc, EndTimeUtc, frequency, Process, NormalizedProcessPath, tostring(ProcessPath), tostring(Computer), tostring(Account)\n| extend NTDomain = split(Account, '\\\\', 0)[0], Name = split(Account, '\\\\', 1)[0], HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain \n```"
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
version: 1.0.1
---

