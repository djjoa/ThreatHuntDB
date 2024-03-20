---
id: d83f40fc-bbcc-4020-8d45-ad2d82355cb2
name: PowerShell downloads
description: |
  'Finds PowerShell execution events that could involve a download'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
  - CommandAndControl
query: "```kusto\nlet ProcessCreationEvents=() {\nlet processEvents=SecurityEvent\n| where EventID==4688\n| project  TimeGenerated, ComputerName=Computer,AccountName=SubjectUserName,        AccountDomain=SubjectDomainName,\n  FileName=tostring(split(NewProcessName, '\\\\')[-1]),\nProcessCommandLine = CommandLine, \nInitiatingProcessFileName=ParentProcessName,InitiatingProcessCommandLine=\"\",InitiatingProcessParentFileName=\"\";\nprocessEvents};\nProcessCreationEvents\n| where FileName in~ (\"powershell.exe\", \"powershell_ise.exe\",\"pwsh.exe\")\n| where ProcessCommandLine has \"Net.WebClient\"\n   or ProcessCommandLine has \"DownloadFile\"\n   or ProcessCommandLine has \"Invoke-WebRequest\"\n   or ProcessCommandLine has \"Invoke-Shellcode\"\n   or ProcessCommandLine contains \"http:\"\n| project TimeGenerated, ComputerName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine\n| top 100 by TimeGenerated\n| extend HostName = tostring(split(ComputerName, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(ComputerName, '.'), 1, -1), '.'))\n| extend Account_0_Name = AccountName\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 2.0.1
---

