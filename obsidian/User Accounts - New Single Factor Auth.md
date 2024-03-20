---
id: 8eace93b-f38c-47b7-a21d-739556d31db6
name: User Accounts - New Single Factor Auth
description: |
  'Identifies users whose single Factor Auth Events in scenarios where it has not been seen before, or where only multi factor auth has been observed.'
description_detailed: |
  'Identifies users whose single Factor Auth Events in scenarios where it has not been seen before, or where only multi factor auth has been observed.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-successful-unusual-sign-ins
  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AADNonInteractiveUserSignInLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
tags:
  - AADSecOpsGuide
query: "```kusto\n\nlet starttime = totimespan('{{StartTimeISO}}');\nlet endtime = totimespan('{{EndTimeISO}}');\nlet isGUID = \"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}\";\nlet lookback = starttime - 7d;\nlet behaviorAnalyticsData = materialize(\n BehaviorAnalytics\n      | where ActivityType in (\"FailedLogOn\", \"LogOn\")\n      | where isnotempty(SourceIPAddress)\n      | project UsersInsights, DevicesInsights, ActivityInsights, InvestigationPriority, SourceIPAddress\n      | project-rename IPAddress = SourceIPAddress\n      | summarize\n          UsersInsights = make_set(UsersInsights, 1000),\n          DevicesInsights = make_set(DevicesInsights, 1000),\n          IPInvestigationPriority = sum(InvestigationPriority)\n      by IPAddress\n);\nlet aadFunc = (tableName:string){\n  table(tableName)\n  | where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))\n  | where not(Identity matches regex isGUID)\n  | where ResultType == 0\n  | where AuthenticationDetails != \"[]\"\n  | extend AuthenticationMethod = tostring(todynamic(AuthenticationDetails)[0].authenticationMethod)\n  | where AuthenticationMethod != \"Previously satisfied\"\n  | join kind=leftouter (\n      behaviorAnalyticsData\n  ) on IPAddress\n  | summarize count(), make_set(AuthenticationRequirement, 1000), make_set(AuthenticationMethod, 1000), make_set(IPAddress, 1000), make_set(Location, 1000), LastLogin = max(TimeGenerated), IPInvestigationPriority = sum(IPInvestigationPriority) by UserPrincipalName\n  | extend noofAuthMehods = array_length(set_AuthenticationMethod), noofAuthReqs = array_length(set_AuthenticationRequirement)\n  | where noofAuthMehods > 1 or noofAuthReqs > 1\n  | extend timestamp = LastLogin, Account_0_Name = UserPrincipalName\n};\nlet aadSignin = aadFunc(\"SigninLogs\");\nlet aadNonInt = aadFunc(\"AADNonInteractiveUserSignInLogs\");\nunion isfuzzy=true aadSignin, aadNonInt \n| sort by IPInvestigationPriority desc\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserPrincipalName
version: 1.0.1
---

