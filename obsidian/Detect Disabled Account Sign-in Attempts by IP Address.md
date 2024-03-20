---
id: 0cd51b2e-d3b2-4001-8e3f-5cbb604f69b2
name: Detect Disabled Account Sign-in Attempts by IP Address
description: |
  'This query searches for failed sign-in attempts to disabled accounts summarized by the IP originating IP address.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\nSigninLogs \n| where ResultType == \"50057\" \n| where ResultDescription =~ \"User account is disabled. The account has been disabled by an administrator.\" \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), numberAccountsTargeted = dcount(UserPrincipalName), \nnumberApplicationsTargeted = dcount(AppDisplayName), accountSet = make_set(UserPrincipalName, 100), applicationSet=make_set(AppDisplayName, 100), \nnumberLoginAttempts = count() by IPAddress\n| extend timestamp = StartTime\n| order by numberLoginAttempts desc\n| extend IP_0_Address = IPAddress\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
version: 1.0.2
---

