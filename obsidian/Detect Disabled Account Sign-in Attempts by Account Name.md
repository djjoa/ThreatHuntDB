---
id: b00f127c-46fa-40bd-9ab6-b266974d29cc
name: Detect Disabled Account Sign-in Attempts by Account Name
description: |
  'This query searches for failed attempts to sign-in to disabled accounts summarized by account name.
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
query: "```kusto\nlet riskScoreCutoff = 20; //Adjust this based on volume of results\nSigninLogs \n| where ResultType == \"50057\" \n| where ResultDescription == \"User account is disabled. The account has been disabled by an administrator.\" \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by AppDisplayName, UserPrincipalName\n| extend timestamp = StartTime, UserPrincipalName = tolower(UserPrincipalName), AccountCustomEntity = UserPrincipalName \n| order by count_ desc\n| join kind=leftouter (\n    IdentityInfo\n    | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN\n    | extend BlastRadiusInt = iif(BlastRadius == \"High\", 1, 0)\n    | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled, BlastRadiusInt\n    | summarize\n        Tags = make_set(Tags, 1000),\n        GroupMembership = make_set(GroupMembership, 1000),\n        AssignedRoles = make_set(AssignedRoles, 1000),\n        BlastRadiusInt = sum(BlastRadiusInt),\n        UserType = make_set(UserType, 1000),\n        UserAccountControl = make_set(UserType, 1000)\n    by AccountUPN\n    | extend UserPrincipalName=tolower(AccountUPN)\n) on UserPrincipalName\n| where BlastRadiusInt > riskScoreCutoff\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 2.0.2
---

