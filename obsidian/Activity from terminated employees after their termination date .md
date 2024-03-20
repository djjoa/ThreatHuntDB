---
id: e091e85d-4376-48cd-9bff-4beaa2ed4280
name: Activity from terminated employees after their termination date
description: |
  'Shows all users tagged as terminated employees in the Terminated Employees watchlist that had activities after their termination date.'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
relevantTechniques:
query: "```kusto\n//Consider creating the watchlist named \"TerminatedEmployees\" having column \"User Principal Name\" with details of terminated employees\n//If you already have watch list with diffrent name then consider modifying the query\n_GetWatchlist('TerminatedEmployees') \n| join kind=innerunique (BehaviorAnalytics) \n  on $left.['User Principal Name'] == $right.UserPrincipalName\n| where TimeGenerated > todatetime(['Termination date'])\n| extend AadUserId = UsersInsights.AccountObjectID\n| extend Account_0_AadUserId = AadUserId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AadUserId
version: 2.0.0
---

