---
id: 8afd1086-fc9a-4d26-b3ff-5c794c79a59a
name: Exchange PowerShell Snapin Added
description: |
  'The Exchange Powershell Snapin was loaded on a host, this allows for a Exchange server management via PowerShell. Whilst this is a legitimate administrative tool it is abused by attackers to performs actions on a compromised Exchange server. Hunt for unusual activity related to this Snapin including it being added on new hosts or by new accounts.'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Collection
relevantTechniques:
  - T1119
query: "```kusto\nSecurityEvent\n| where EventID == 4688\n| where Process has_any (\"cmd.exe\", \"powershell.exe\", \"PowerShell_ISE.exe\")\n| where isnotempty(CommandLine)  \n| where CommandLine has \"Add-PSSnapin Microsoft.Exchange.Management.Powershell.Snapin\"\n| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Computer, Account, CommandLine\n| extend NTDomain = tostring(split(Account,'\\\\',0)[0]), Name = tostring(split(Account,'\\\\',1)[0])  \n| extend timestamp = FirstSeen\n| extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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
version: 2.0.1
---

