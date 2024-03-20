---
id: 6962473c-bcb8-421d-a0db-826078cad280
name: Unfamiliar Signin Correlation with AzurePortal Signin Attempts and AuditLogs
description: |
  'This query looks for unfamiliar Sign-in's thats not seen recently for the given user
   with azure portal login attempts and audit logs to help detect and reduce the analysis timeline for defenders'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AADNonInteractiveUserSignInLogs
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert (ASC)
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - InitialAccess
  - Impact
relevantTechniques:
  - T1190
  - T1078
query: "```kusto\nSecurityAlert \n| where AlertName == \"Unfamiliar sign-in properties\"\n| extend Extprop = parsejson(Entities)\n| mv-expand Extprop\n| extend Extprop = parsejson(Extprop)\n| extend CmdLine = iff(Extprop['Type']==\"process\", Extprop['CommandLine'], '')\n| extend File = iff(Extprop['Type']==\"file\", Extprop['Name'], '')\n| extend Account = Extprop['Name']\n| extend Domain = Extprop['UPNSuffix']\n| extend Account = iif(isnotempty(Domain) and Extprop['Type']==\"account\", tolower(strcat(Account, \"@\", Domain)), iif(Extprop['Type']==\"account\", tolower(Account), \"\"))\n| extend IpAddress = iff(Extprop[\"Type\"] == \"ip\",Extprop['Address'], '')\n| extend Process = iff(isnotempty(CmdLine), CmdLine, File)\n| summarize count() by AlertName,AlertSeverity,CompromisedEntity,Account\n| join kind=inner\n(\nSigninLogs\n| where AppDisplayName == \"Azure Portal\"\n// 50126 - Invalid username or password, or invalid on-premises username or password.\n| where ResultType == \"50126\"\n| extend OS = tostring(DeviceDetail.operatingSystem), Browser = tostring(DeviceDetail.browser)\n| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)\n| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)\n| project  UserDisplayName, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, StatusCode, StatusDetails, Location, State,IPAddress\n| extend AccountCustomEntity = UserPrincipalName\n) on $left.Account == $right.AccountCustomEntity\n| project AccountCustomEntity = tolower(AccountCustomEntity),State,StatusCode,StatusDetails,IPAddress,ResultDescription,AppDisplayName,Location,AlertName\n| join kind=inner\n(\nAuditLogs\n| where Category =~ \"RoleManagement\"\n| where OperationName has_any (\"Add member to role\",\"Add member to role in PIM requested (permanent)\")\n| extend IpAddress = case(\n  isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), \n  isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),\n  'Not Available')\n| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \n  tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName)) \n| project InitiatedBy = tolower(InitiatedBy), ActivityDateTime, ActivityDisplayName,IpAddress, AADOperationType, AADTenantId\n) on $left.AccountCustomEntity == $right.InitiatedBy\n| project AccountCustomEntity,AppDisplayName,IPAddress,Location,StatusCode,StatusDetails\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
---

