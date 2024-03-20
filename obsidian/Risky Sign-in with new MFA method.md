---
id: bfacf634-c75e-4291-998c-ecbc0323d943
name: Risky Sign-in with new MFA method
description: |
  'This query identifies new MFA methods added to an account within 6 hours of a medium or high risk sign-in session. It includes UEBA logs IdentityInfo and BehaviorAnalytics for context.'
description_detailed: 'Looks for a new MFA method added to an account that was preceded by medium or high risk sign-in session for the same user within maximum 6h timeframe.  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
      - SigninLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: BehaviorAnalytics
    dataTypes:
      - IdentityInfo
tactics:
  - Persistence
relevantTechniques:
  - T1078.004
query: "```kusto\nlet timeDelta = 6h;\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet mfaMethodAdded=AuditLogs\n| where TimeGenerated between (starttime .. endtime)\n| where OperationName =~ \"Update user\" \n| where TargetResources has \"StrongAuthenticationPhoneAppDetail\"\n| extend AccountUpn = tostring(TargetResources[0].userPrincipalName)\n| extend AccountObjectId = tostring(TargetResources[0].id)\n| project MfaAddedTimestamp=TimeGenerated,AccountUpn,AccountObjectId;\nlet usersWithNewMFAMethod=mfaMethodAdded\n| distinct AccountObjectId;\nlet hasusersWithNewMFAMethod = isnotempty(toscalar(usersWithNewMFAMethod));\nlet riskySignins=SigninLogs\n| where TimeGenerated between ((starttime-timeDelta) .. endtime)\n| where hasusersWithNewMFAMethod\n| where UserId in (usersWithNewMFAMethod) \n| where RiskLevelDuringSignIn has_any ('medium', 'high')\n| where AppDisplayName in~ (\"Office 365 Exchange Online\", \"OfficeHome\") \n| where isnotempty(Id) \n| project SignInTimestamp=TimeGenerated, AppDisplayName, CorrelationId, AccountObjectId=UserId, IPAddress, RiskLevelDuringSignIn \n| summarize SignInTimestamp=argmin(SignInTimestamp,*) by AppDisplayName, CorrelationId, AccountObjectId, IPAddress, RiskLevelDuringSignIn;\nmfaMethodAdded \n| join riskySignins on AccountObjectId \n| where  MfaAddedTimestamp - SignInTimestamp < timeDelta //Time delta between risky sign-in and device registration less than 6h \n| project-away AccountObjectId1\n| extend timestamp = MfaAddedTimestamp, AccountCustomEntity = tolower(AccountUpn), IPCustomEntity = IPAddress\n| join kind=leftouter (\n    IdentityInfo\n    | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN\n    | extend BlastRadiusInt = iif(BlastRadius == \"High\", 1, 0)\n    | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled, BlastRadiusInt\n    | summarize\n        Tags = make_set(Tags, 1000),\n        GroupMembership = make_set(GroupMembership, 1000),\n        AssignedRoles = make_set(AssignedRoles, 1000),\n        BlastRadiusInt = sum(BlastRadiusInt),\n        UserType = make_set(UserType, 1000),\n        UserAccountControl = make_set(UserType, 1000)\n    by AccountUPN\n    | extend UserPrincipalName=tolower(AccountUPN)\n    | project-rename AccountCustomEntity = AccountUPN\n) on AccountCustomEntity\n| join kind=leftouter (\n    BehaviorAnalytics\n    | where ActivityType in (\"FailedLogOn\", \"LogOn\")\n    | where isnotempty(SourceIPAddress)\n    | project UsersInsights, DevicesInsights, ActivityInsights, InvestigationPriority, SourceIPAddress\n    | project-rename IPAddress = SourceIPAddress\n    | summarize\n        UsersInsights = make_set(UsersInsights, 1000),\n        DevicesInsights = make_set(DevicesInsights, 1000),\n        IPInvestigationPriority = sum(InvestigationPriority)\n    by IPAddress)\non IPAddress\n| extend Account_0_Name = AccountCustomEntity\n| extend Account_0_AadUserId = AccountObjectId\n| extend IP_0_Address = IPAddress\n| extend UEBARiskScore = BlastRadiusInt + IPInvestigationPriority\n| sort by UEBARiskScore desc \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
      - identifier: AadUserId
        columnName: AccountObjectId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
version: 2.0.1
---

