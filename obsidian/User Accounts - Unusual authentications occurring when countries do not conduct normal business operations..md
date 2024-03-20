---
id: f56b2223-0d4d-4347-9de4-822d195624ee
name: User Accounts - Unusual authentications occurring when countries do not conduct normal business operations.
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
  - connectorId: BehaviorAnalytics
    dataTypes:
      - IdentityInfo
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
tags:
  - AADSecOpsGuide
query: "```kusto\nlet starttime = totimespan('{{StartTimeISO}}');\nlet endtime = totimespan('{{EndTimeISO}}');\nlet isGUID = \"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}\";\nlet userthreshold = 25;\nlet HistLogons = SigninLogs\n| where IsInteractive == true\n| where TimeGenerated between (startofday(ago(starttime))..startofday(ago(endtime)))\n| extend HourOfLogin = hourofday(TimeGenerated), DayNumberofWeek = dayofweek(TimeGenerated)\n| extend DayofWeek = case(\n  DayNumberofWeek == \"00:00:00\", \"Sunday\", \n  DayNumberofWeek == \"1.00:00:00\", \"Monday\", \n  DayNumberofWeek == \"2.00:00:00\", \"Tuesday\", \n  DayNumberofWeek == \"3.00:00:00\", \"Wednesday\", \n  DayNumberofWeek == \"4.00:00:00\", \"Thursday\", \n  DayNumberofWeek == \"5.00:00:00\", \"Friday\", \n  DayNumberofWeek == \"6.00:00:00\", \"Saturday\",\"InvalidTimeStamp\")\n| summarize UserCount = dcount(UserPrincipalName) by HourOfLogin, Location, DayofWeek\n| where UserCount > userthreshold;\nHistLogons\n| join kind = rightanti (\nSigninLogs\n| where IsInteractive == true\n| where TimeGenerated > ago(1d)\n| extend HourOfLogin = hourofday(TimeGenerated), DayNumberofWeek = dayofweek(TimeGenerated)\n| extend DayofWeek = case(\n  DayNumberofWeek == \"00:00:00\", \"Sunday\", \n  DayNumberofWeek == \"1.00:00:00\", \"Monday\", \n  DayNumberofWeek == \"2.00:00:00\", \"Tuesday\", \n  DayNumberofWeek == \"3.00:00:00\", \"Wednesday\", \n  DayNumberofWeek == \"4.00:00:00\", \"Thursday\", \n  DayNumberofWeek == \"5.00:00:00\", \"Friday\", \n  DayNumberofWeek == \"6.00:00:00\", \"Saturday\",\"InvalidTimeStamp\")\n  | summarize count(), FirstSuccessfulSignin = min(TimeGenerated), LastSuccessfulSignin = max(TimeGenerated), make_set(IPAddress), make_set(ClientAppUsed), make_set(UserAgent), make_set(AppDisplayName) by HourOfLogin, Location, DayofWeek, UserPrincipalName\n  ) on Location, DayofWeek , HourOfLogin\n  | extend timestamp = LastSuccessfulSignin, Account_0_Name = UserPrincipalName\n| join kind=leftouter (\n    IdentityInfo\n    | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN\n    | extend BlastRadiusInt = iif(BlastRadius == \"High\", 1, 0)\n    | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled, BlastRadiusInt\n    | summarize\n        Tags = make_set(Tags, 1000),\n        GroupMembership = make_set(GroupMembership, 1000),\n        AssignedRoles = make_set(AssignedRoles, 1000),\n        BlastRadiusInt = sum(BlastRadiusInt),\n        UserType = make_set(UserType, 1000),\n        UserAccountControl = make_set(UserType, 1000)\n    by AccountUPN\n    | extend UserPrincipalName=tolower(AccountUPN)\n) on UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserPrincipalName
version: 1.0.1
---

