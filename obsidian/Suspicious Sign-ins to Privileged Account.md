---
id: a73c52f2-b3a5-4fe4-be7d-4d59b8558590
name: Suspicious Sign-ins to Privileged Account
description: |
  'This query identifies sign-ins from non-compliant or MFA-less devices to privileged accounts using a pre-built watchlist. Microsoft Sentinel offers customizable watchlist templates for your environment.'
description-detailed: |
  'This query searches for any Sign-ins from non-compliant device/device registered without MFA(Multi-factor Authentication)/unknown device to privileged account using pre-built watchlist to identify accounts.
  Microsoft Sentinel now provides built-in watchlist templates, that can be customized for your environment and used during investigations.
  Reference: https://techcommunity.microsoft.com/t5/azure-sentinel/what-s-new-watchlists-templates-are-now-in-public-preview/ba-p/2614340'
  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: BehaviorAnalytics
    dataTypes:
      - IdentityInfo
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\nlet priv_users = ('_GetWatchlist(\"VIPUsers\")') ;\n(union isfuzzy=true\n(SigninLogs //when a device is registered/joined without MFA \n| where AuthenticationRequirement == \"multiFactorAuthentication\"\n| where ResourceDisplayName == \"Device Registration Service\" \n| where ConditionalAccessStatus == \"success\"\n| extend AccountName = tolower(split(UserPrincipalName, \"@\")[0]), WinSecEventDomain = \"-\"\n| where AccountName in (priv_users)\n| project-rename  ServiceOrSystem = AppDisplayName, ClientIP = IPAddress), \n(\n(SigninLogs //Sign-ins by non-compliant devices\n| where DeviceDetail.isCompliant == false\n| where ConditionalAccessStatus == \"success\"\n  | extend AccountName = tolower(split(UserPrincipalName, \"@\")[0]), WinSecEventDomain = \"-\"\n  | where AccountName in (priv_users)\n  | project-rename  ServiceOrSystem = AppDisplayName, ClientIP = IPAddress)\n),\n(SigninLogs //Sign-ins by unknown devices\n| where isempty(DeviceDetail.deviceId)\n| where AuthenticationRequirement == \"singleFactorAuthentication\"\n| where ResultType == \"0\"\n| where NetworkLocationDetails == \"[]\"\n| extend AccountName = tolower(split(UserPrincipalName, \"@\")[0]), WinSecEventDomain = \"-\"\n| where AccountName in (priv_users)\n| project-rename  ServiceOrSystem = AppDisplayName, ClientIP = IPAddress)\n)\n| project AccountCustomEntity =tolower(AccountName), AppId, Category, IPCustomEntity = ClientIP, CorrelationId, ResourceCustomEntity = ResourceId, Identity\n| join kind=leftouter (\n      IdentityInfo\n      | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN\n      | extend BlastRadiusInt = iif(BlastRadius == \"High\", 1, 0)\n      | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled, BlastRadiusInt\n      | summarize\n          Tags = make_set(Tags, 1000),\n          GroupMembership = make_set(GroupMembership, 1000),\n          AssignedRoles = make_set(AssignedRoles, 1000),\n          BlastRadiusInt = sum(BlastRadiusInt),\n          UserType = make_set(UserType, 1000),\n          UserAccountControl = make_set(UserType, 1000)\n      by AccountUPN\n      | extend AccountCustomEntity = tolower(AccountUPN)\n) on AccountCustomEntity\n| join kind=leftouter (\n      BehaviorAnalytics\n      | where ActivityType in (\"FailedLogOn\", \"LogOn\")\n      | where isnotempty(SourceIPAddress)\n      | project UsersInsights, DevicesInsights, ActivityInsights, InvestigationPriority, SourceIPAddress\n      | project-rename IPCustomEntity = SourceIPAddress\n      | summarize\n        UsersInsights = make_set(UsersInsights, 1000),\n        DevicesInsights = make_set(DevicesInsights, 1000),\n        IPInvestigationPriority = sum(InvestigationPriority)\n      by IPCustomEntity\n) on IPCustomEntity\n| extend UEBARiskScore = BlastRadiusInt + IPInvestigationPriority\n| sort by UEBARiskScore desc\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceCustomEntity
version: 1.0.1
---

