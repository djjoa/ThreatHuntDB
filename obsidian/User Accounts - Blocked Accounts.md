---
id: dbc82bc1-c7df-44e3-838a-5846a313cf35
name: User Accounts - Blocked Accounts
description: |
  'An account could be blocked/locked out due to multiple reasons. This hunting query summarize blocked/lockout accounts and checks if most recent signin events for them is after last blocked accounts
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-successful-unusual-sign-ins'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AADNonInteractiveUserSignInLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
tags:
  - AADSecOpsGuide
query: "```kusto\nlet starttime = totimespan('{{StartTimeISO}}');\nlet endtime = totimespan('{{EndTimeISO}}');\nlet lookback = starttime - 7d;\nlet isGUID = \"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}\";\nlet aadFunc = (tableName:string){\n  table(tableName)\n  | where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))\n  | where not(Identity matches regex isGUID)\n};\nlet aadSignin = aadFunc(\"SigninLogs\");\nlet aadNonInt = aadFunc(\"AADNonInteractiveUserSignInLogs\");\nlet blocked_users = \nunion isfuzzy=true aadSignin, aadNonInt \n// Blocked or locked account due to failed attempts for various reasons.\n| where ResultType != \"0\"\n| where ResultDescription has_any (\"blocked\", \"locked\")  or ResultType in (50053, 50131, 53003, 500121)\n| summarize FirstBlockedAttempt = min(TimeGenerated), LastBlockedAttempt = max(TimeGenerated) by UserPrincipalName, ResultDescription, ResultType;\nblocked_users\n| join kind= inner (\nunion isfuzzy=true aadSignin, aadNonInt\n| where ResultType == 0\n| summarize FirstSuccessfulSignin = min(TimeGenerated), LastSuccessfulSignin = max(TimeGenerated), make_set(IPAddress), make_set(ClientAppUsed), make_set(UserAgent), make_set(AppDisplayName) by UserPrincipalName, UserDisplayName\n) on UserPrincipalName\n| where LastSuccessfulSignin > LastBlockedAttempt //Checking if successul login is after lastblockedattempts\n| extend timestamp = LastSuccessfulSignin, AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
---

