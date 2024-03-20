---
id: 24ae555c-5e33-4b5d-827a-44206e39f6b4
name: Potential Impacket Execution
description: |
  'This hunting query identifies execution of Impacket tool. Impacket is a popular tool used by attackers for remote service execution,     Kerberos   manipulation and Windows credential dumping.'
description-detailed: |
  'This hunting query identifies execution of Impacket tool. Impacket is a popular tool used by attackers for remote service execution, Kerberos  manipulation and Windows credential dumping.
    Refrence: https://twitter.com/SBousseaden/status/1286750095296335883'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - CredentialAccess
relevantTechniques:
  - T1557.001
  - T1040
  - T1003.001
  - T1003.002
  - T1003.003
  - T1003.004
  - T1558.003
query: "```kusto\n(union isfuzzy=true\n(SecurityEvent\n| where EventID == '5145'\n| where RelativeTargetName has 'SYSTEM32' and RelativeTargetName endswith @\".tmp\"\n| where ShareName has \"\\\\\\\\*\\\\ADMIN$\"\n),\n(WindowsEvent\n| where EventID == '5145' \n| extend RelativeTargetName= tostring(EventData.RelativeTargetName)\n| extend ShareName= tostring(EventData.ShareName)\n| where RelativeTargetName has 'SYSTEM32' and RelativeTargetName endswith @\".tmp\"\n| where ShareName has \"\\\\\\\\*\\\\ADMIN$\"\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n)\n)\n| extend timestamp = TimeGenerated \n| extend NTDomain = split(Account, '\\\\', 0)[0], UserName = split(Account, '\\\\', 1)[0]\n| extend HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Account_0_Name = UserName\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

