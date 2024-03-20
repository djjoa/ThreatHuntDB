---
id: cf83633e-5dfd-4887-993b-c910452439da
name: Failed attempt to access Azure Portal
description: |
  'Access attempts to Azure Portal from an unauthorized user. Either invalid password or the user account does not exist.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nSigninLogs\n| where AppDisplayName contains \"Azure Portal\"\n// 50126 - Invalid username or password, or invalid on-premises username or password.\n// 50020? - The user doesn't exist in the tenant.\n| where ResultType in ( \"50126\" , \"50020\")\n| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser\n| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)\n| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPAddresses = makeset(IPAddress), DistinctIPCount = dcount(IPAddress), \nmakeset(OS), makeset(Browser), makeset(City), AttemptCount = count() \nby UserDisplayName, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, StatusCode, StatusDetails, Location, State\n| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName\n| sort by AttemptCount\n```"
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

