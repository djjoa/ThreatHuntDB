---
id: 847c2652-547d-4d5f-9b71-d2f8d81eac62
name: Inactive or new account signins
description: |
  'Query for new sign-ins from stale/inactive accounts. UEBA filters based on ActivityInsights. Results for accounts created in the last 7 days are filtered out.'
description_detailed: "'Query for accounts seen signing in for the first time. These could be associated with stale/inactive accounts that ought to have been deleted \nbut were not and may have been subsequently compromised.\nUEBA is used to filter out based on ActivityInsights where we see certain First Time User events identified as true.\nResults for user accounts created in the last 7 days are filtered out.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
      - AuditLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 14d;\nlet midtime = starttime - 7d;\nlet SigninsSummary = SigninLogs\n| where TimeGenerated between(starttime..endtime)\n// successful sign-in only\n| where ResultType == 0\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), SigninLogs_ItemIds = make_set(_ItemId), loginCountToday=count() by UserPrincipalName, UserId, UserType, IPAddress\n| join kind=leftanti (\n   SigninLogs\n   // historical successful sign-in\n   | where TimeGenerated between(lookback..starttime)\n   | where ResultType == 0\n   | summarize by UserId\n) on UserId;\n// need to help BehaviorAnalytics query to limit only to Signins we are interested in\nlet onlyInactive = SigninsSummary | summarize make_set(UserPrincipalName);\nlet SigninsWithUEBA =\nBehaviorAnalytics\n| where TimeGenerated between(starttime..endtime)\n| where ActionType in ('Sign-in','InteractiveLogon')\n| where UserPrincipalName in~ (onlyInactive)\n| extend ActivityInsights = parse_xml(ActivityInsights)\n// only looked where FirstTimeUser items are True\n| where ActivityInsights matches regex '\\\"FirstTimeUser([A-Za-z0-9]+)\\\":\\\"True\\\"'\n// only exclude when Uncommon Among Peers is false as this helps remove expected first time usage, exception is we always show FirstTimeUserConnectedFromCountry == True\n// also always keep InvestigationPriority if 1 or more\n| where (not(ActivityInsights.FirstTimeUserUsedApp == 'True' and ActivityInsights.AppUncommonlyUsedAmongPeers == 'False') or InvestigationPriority > 0)\n| where (not(ActivityInsights.FirstTimeUserConnectedViaBrowser == 'True' and ActivityInsights.BrowserUncommonlyUsedAmongPeers == 'False') or InvestigationPriority > 0)\n| where (not(ActivityInsights.FirstTimeUserAccessedResource == 'True' and ActivityInsights.ResourceUncommonlyUsedAmongPeers == 'False') or InvestigationPriority > 0)\n// for ISP, it makes more sense to exclude if Uncommon in Tenant or Uncommon among peers is false.\n| where (not(ActivityInsights.FirstTimeUserConnectedViaISP == 'True' and (ActivityInsights.ISPUncommonlyUsedInTenant == 'False' or ActivityInsights.ISPUncommonlyUsedAmongPeers == 'False')) or InvestigationPriority > 0)\n| extend UEBA_Insights = pack_dictionary(\"TimeGenerated\", TimeGenerated, \"ActivityInsights\", ActivityInsights, \"UsersInsights\", UsersInsights, \"DevicesInsights\", DevicesInsights)\n| summarize UEBA_ItemIds = make_set(_ItemId), UEBA_SourceRecordIds = make_set(SourceRecordId), UEBA_Insights = make_set(UEBA_Insights) by\nUEBA_UserPrincipalName = UserPrincipalName, JoinedWithType = Type, UEBA_ActionType = ActionType, UEBA_SourceIPAddress = SourceIPAddress, UEBA_SourceIPLocation = SourceIPLocation, UEBA_InvestigationPriority = InvestigationPriority\n| extend UEBA_Info = pack_dictionary(\"UEBA_Insights\", UEBA_Insights, \"UEBA_ItemIds\", UEBA_ItemIds, \"UEBA_SourceRecordIds\", UEBA_SourceRecordIds)\n| project-away UEBA_ItemIds, UEBA_SourceRecordIds, UEBA_Insights\n| join kind=inner ( \n  SigninsSummary\n) on $left.UEBA_UserPrincipalName == $right.UserPrincipalName, $left.UEBA_SourceIPAddress == $right.IPAddress\n| project-reorder StartTime, EndTime, UserPrincipalName, UserId, IPAddress, UserType, loginCountToday, JoinedWithType\n;\nSigninsWithUEBA \n| join kind= leftanti (\n   // filter out newly created user accounts from last 7 days\n   AuditLogs\n   | where TimeGenerated between(midtime..endtime)\n   | where OperationName == \"Add user\"\n   | summarize by NewUserId = tostring(TargetResources[0].id)\n) on $left.UserId == $right.NewUserId\n| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other", "Identity"]
---

