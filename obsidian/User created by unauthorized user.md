---
id: 42ae9690-89ce-4063-9a90-465badad5395
name: User created by unauthorized user
description: |
  'User account created by an unauthorized user, pass in a list'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098
  - T1078
query: "```kusto\n// Create DataTable with your own values, example below shows dummy usernames that are authorized and for what domain\nlet List = datatable(AuthorizedUser:string, Domain:string)[\"Bob\", \"Domain\", \"joe\", \"domain\", \"MATT\", \"DOMAIN\"];\nSecurityEvent\n| where EventID == 4720\n| where AccountType == \"User\"\n| join kind= leftanti (\n    List\n    | project SubjectUserName = tolower(AuthorizedUser), SubjectDomainName = toupper(Domain)\n) on SubjectUserName, SubjectDomainName\n| project TimeGenerated, Computer, Account, SubjectUserName, SubjectDomainName, TargetAccount, EventID, Activity\n| extend timestamp = TimeGenerated, HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))\n| extend Account_0_Name = SubjectUserName\n| extend Account_0_NTDomain = SubjectDomainName\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain \n```"
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

