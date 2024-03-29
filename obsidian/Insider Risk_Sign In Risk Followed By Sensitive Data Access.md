---
id: 45ec52c2-99e1-4de1-9adc-bae0f79d4e23
name: Insider Risk_Sign In Risk Followed By Sensitive Data Access
description: |
  'This query correlates a risky user sign ins with access to sensitive data classified by data loss prevention capabilities (watchlist configurable). For more information, see https://docs.microsoft.com/azure/sentinel/watchlists'
requiredDataConnectors:
  - connectorId: AzureInformationProtection
    dataTypes:
      - InformationProtectionLogs_CL
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - Exfiltration
relevantTechniques:
  - T1567
query: |-
  ```kusto
  let RiskySignIns = SigninLogs
  | where RiskState == "atRisk"
  | where RiskLevelDuringSignIn == "high" or RiskLevelDuringSignIn == "medium"
  | extend RiskTypes = strcat(RiskEventTypes_V2);
  InformationProtectionLogs_CL
  | extend UserPrincipalName = UserId_s
  | where LabelName_s <> ""
  | join kind=inner (SigninLogs) on UserPrincipalName
  | extend City = tostring(LocationDetails.city)
  // | where City <> "New York" // Configure Location Details within Organizational Requirements
  | extend State = tostring(LocationDetails.state)
  // | where State <> "Texas" // Configure Location Details within Organizational Requirements
  | extend Country_Region = tostring(LocationDetails.countryOrRegion)
  // | where Country_Region <> "US" // Configure Location Details within Organizational Requirements
  // | lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey
  | summarize count() by UserPrincipalName, LabelName_s, Activity_s, City, State, Country_Region, TimeGenerated
  | join kind=inner (RiskySignIns) on UserPrincipalName
  // | lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey
  | project UserPrincipalName, RiskTypes, City, State, Country_Region, LabelName_s, Activity_s, count_, TimeGenerated
  | sort by count_ desc
  | limit 100
  | extend AccountCustomEntity = UserPrincipalName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountCustomEntity
---

