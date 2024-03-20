---
id: 4eb6d052-9873-4092-b989-66eae780e203
name: Signin Logs with expanded Conditional Access Policies
description: |
  'Example query for SigninLogs showing how to break out packed fields.  In this case extending conditional access Policies '
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - Impact
query: "```kusto\n\nSigninLogs \n| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser\n| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)\n| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)\n| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)\n| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)\n| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)\n| extend Date = startofday(TimeGenerated), Hour = datetime_part(\"Hour\", TimeGenerated)\n| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, \nConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, \nLocation, State, City\n| extend timestamp = Date, AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress\n| sort by Date \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
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

