---
id: 7f6e8f14-62fa-4ce6-a490-c07f1d9888ba
name: Anomalous sign-in location by user account and authenticating application - with sign-in details
description: |
  'This query examines Microsoft Entra ID sign-ins and identifies anomalous changes in a user's location profile. A variation joins results back onto the original sign-in data to review the location set with each identified user in tabular form.'
description_detailed: "'This query over Microsoft Entra ID sign-in considers all user sign-ins for each Azure Active \nDirectory application and picks out the most anomalous change in location profile for a user within an \nindividual application. The intent is to hunt for user account compromise, possibly via a specific application\nvector.\nThis variation of the query joins the results back onto the original sign-in data to allow review of the \nlocation set with each identified user in tabular form.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nSigninLogs \n// Forces Log Analytics to recognize that the query should be run over full time range\n| extend  locationString= strcat(tostring(LocationDetails[\"countryOrRegion\"]), \"/\", \ntostring(LocationDetails[\"state\"]), \"/\", tostring(LocationDetails[\"city\"]), \";\") \n| project TimeGenerated, AppDisplayName , UserPrincipalName, locationString \n// Create time series \n| make-series dLocationCount = dcount(locationString) on TimeGenerated step 1d \nby UserPrincipalName, AppDisplayName \n// Compute best fit line for each entry \n| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit)=series_fit_line(dLocationCount) \n// Chart the 3 most interesting lines  \n// A 0-value slope corresponds to an account being completely stable over time for a given Azure Active Directory application\n| top 3 by Slope desc  \n// Extract the set of locations for each top user:\n| join kind=inner (SigninLogs\n| extend  locationString= strcat(tostring(LocationDetails[\"countryOrRegion\"]), \"/\", \ntostring(LocationDetails[\"state\"]), \"/\", tostring(LocationDetails[\"city\"]), \";\")\n| summarize locationList = makeset(locationString), threeDayWindowLocationCount=dcount(locationString) by AppDisplayName, UserPrincipalName, \ntimerange=bin(TimeGenerated, 3d)) on AppDisplayName, UserPrincipalName\n| order by UserPrincipalName, timerange asc\n| project timerange, AppDisplayName , UserPrincipalName, threeDayWindowLocationCount, locationList \n| order by AppDisplayName, UserPrincipalName, timerange asc\n| extend timestamp = timerange, AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
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

