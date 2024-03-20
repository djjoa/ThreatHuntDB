---
id: e8d36582-c403-4466-bd44-ebede5b6fa6e
name: VIP account more than 6 failed logons in 10
description: |
  'VIP Account with more than 6 failed logon attempts in 10 minutes, include your own VIP list in the table below'
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
  - T1110
query: "```kusto\n// Create DataTable with your own values, example below shows dummy usernames that are authorized and for what domain\nlet List = datatable(VIPUser:string, Domain:string)[\"Bob\", \"Domain\", \"joe\", \"domain\", \"MATT\", \"DOMAIN\"];\nList | extend Account = strcat(Domain,\"\\\\\",VIPUser) | join kind= inner (\nSecurityEvent \n| where EventID == \"4625\"\n| where AccountType == \"User\"\n| where LogonType == \"2\" or LogonType == \"3\"\n) on Account \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), FailedVIPLogons = count() by LogonType, Account\n| where FailedVIPLogons >= 6\n| extend timestamp = StartTimeUtc, NTDomain = tostring(split(Account, '\\\\', 0)[0]), UserName = tostring(split(Account, '\\\\', 1)[0])\n| extend Account_0_NTDomain = NTDomain \n| extend Account_0_Name = UserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
      - identifier: NTDomain
        columnName: NTDomain
version: 1.0.1
---

