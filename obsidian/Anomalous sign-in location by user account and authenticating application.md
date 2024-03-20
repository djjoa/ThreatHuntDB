---
id: 8159c663-6724-41b8-9ae8-b328aa8d0c4c
name: Anomalous sign-in location by user account and authenticating application
description: |
  'This query examines Microsoft Entra ID sign-ins for each application and identifies the most anomalous change in a user's location profile. The goal is to detect user account compromise, possibly via a specific application vector.'
description_detailed: "'This query over Microsoft Entra ID sign-in considers all user sign-ins for each Azure Active \nDirectory application and picks out the most anomalous change in location profile for a user within an \nindividual application. The intent is to hunt for user account compromise, possibly via a specific application\nvector.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nSigninLogs \n// Forces Log Analytics to recognize that the query should be run over full time range\n| extend  locationString= strcat(tostring(LocationDetails[\"countryOrRegion\"]), \"/\", \ntostring(LocationDetails[\"state\"]), \"/\", tostring(LocationDetails[\"city\"]), \";\") \n| project TimeGenerated, AppDisplayName, UserPrincipalName, locationString \n// Create time series \n| make-series dLocationCount = dcount(locationString) on TimeGenerated step 1d\nby UserPrincipalName, AppDisplayName \n// Compute best fit line for each entry \n| extend (RSquare, Slope, Variance, RVariance, Interception, LineFit) = series_fit_line(dLocationCount) \n// Chart the 3 most interesting lines  \n// A 0-value slope corresponds to an account being completely stable over time for a given Azure Active Directory application\n| top 3 by Slope desc\n| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName \n| render timechart\n```"
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

