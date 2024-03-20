---
id: 73ac88c0-f073-4b23-8ac4-9f40ea11308d
name: Anomalous Microsoft Entra ID apps based on authentication location
description: "'This query over Microsoft Entra ID sign-in activity highlights Microsoft Entra ID apps with \nan unusually high ratio of distinct geolocations versus total number of authentications'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nlet azureSignIns = \nSigninLogs\n| where SourceSystem == \"Azure AD\"\n| where OperationName == \"Sign-in activity\"\n| project TimeGenerated, OperationName, AppDisplayName , Identity, UserId, UserPrincipalName, Location, LocationDetails, \nClientAppUsed, DeviceDetail, ConditionalAccessPolicies;\nazureSignIns\n| extend locationString = strcat(tostring(LocationDetails[\"countryOrRegion\"]), \"/\", \ntostring(LocationDetails[\"state\"]), \"/\", tostring(LocationDetails[\"city\"]), \";\" , tostring(LocationDetails[\"geoCoordinates\"]))\n| summarize rawSigninCount = count(), countByAccount = dcount(UserId), locationCount = dcount(locationString) by AppDisplayName\n// tail - pick a threshold to rule out the very-high volume Azure AD apps\n| where rawSigninCount < 1000\n// more locations than accounts\n| where locationCount>countByAccount\n// almost as many / more locations than sign-ins!\n| where 1.0*rawSigninCount / locationCount > 0.8 \n| order by rawSigninCount  desc\n| join kind = leftouter (\n   azureSignIns \n) on AppDisplayName \n| project AppDisplayName, TimeGenerated , Identity, rawSigninCount, countByAccount, locationCount,  \nlocationString = strcat(tostring(LocationDetails[\"countryOrRegion\"]), \"/\", tostring(LocationDetails[\"state\"]), \"/\", \ntostring(LocationDetails[\"city\"]), \";\" , tostring(LocationDetails[\"geoCoordinates\"])), UserPrincipalName\n| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName \n| order by AppDisplayName, TimeGenerated desc\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
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

