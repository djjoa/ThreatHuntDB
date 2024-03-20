---
id: 87c1f90a-f868-4528-a9c1-15520249cae6
name: Nishang Reverse TCP Shell in Base64
description: |
  'This query searches for Base64-encoded commands associated with the Nishang reverse TCP shell.
  Ref: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Exfiltration
relevantTechniques:
  - T1011
query: "```kusto\nSecurityEvent\n| where EventID == 4688\n| where Process in(\"powershell.exe\",\"powershell_ise.exe\") and CommandLine has \"-e\" \n| mv-expand SS = split(CommandLine, \" \") \n| where SS matches regex \"[A-Za-z0-9+/]{50,}[=]{0,2}\" \n| extend DecodeString = base64_decode_tostring(tostring(SS)) \n| extend FinalString = replace(\"\\\\0\", \"\", DecodeString) \n| where FinalString has \"tcpclient\" and FinalString contains \"$\" and (FinalString contains \"invoke\" or FinalString contains \"iex\") \n| extend timestamp = TimeGenerated, HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Account_0_Name = SubjectUserName\n| extend Account_0_NTDomain = SubjectDomainName\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: SubjectUserName
      - identifier: NTDomain
        columnName: SubjectDomainName
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.1
---

