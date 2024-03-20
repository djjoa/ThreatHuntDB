---
id: f0ad3b3f-72ac-48b1-9f01-ad408b3af88e
name: Terminated employee accessing High Value Asset
description: |
  'Shows all users tagged as terminated employees in the Terminated Employees watchlist that had activities after their termination date.'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
relevantTechniques:
query: "```kusto\n//Consider creating the watchlist named \"TerminatedEmployees\" and \"HighValueAssets\" having column \"User Principal Name\" and \"Asset Name\" with details of terminated employees\n//If you already have watchlist with different name then consider modifying the query\n_GetWatchlist('HighValueAssets')\n| join kind=innerunique ( BehaviorAnalytics \n        | where ActionType has \"ResourceAccess\") \n        on $left.['Asset Name'] == $right.DestinationDevice\n| join kind=innerunique _GetWatchlist('TerminatedEmployees')\n  on $left.UserPrincipalName == $right.['User Principal Name']\n| extend AadUserId = UsersInsights.AccountObjectID\n| extend Account_0_AadUserId = AadUserId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AadUserId
version: 2.0.0
---

