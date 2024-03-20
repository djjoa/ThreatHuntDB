---
id: f19f913f-292a-41ed-9ac0-f3ea5e703d36
name: Storage Account Key Enumeration
description: "'This query identifies attackers trying to enumerate the Storage keys as well as updating roles using AzureActivity,SigninLogs \nand  AuditLogs'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - InitialAccess
  - LateralMovement
relevantTechniques:
  - T1586
  - T1570
query: "```kusto\nSigninLogs \n | where ResultType == \"0\" \n | where AppDisplayName !in (\"Office 365 Exchange Online\", \"Skype for Business Online\", \"Office 365 SharePoint Online\")\n | project  SuccessLogonTime = TimeGenerated,UserPrincipalName, IPAddress,SuccessAppDisplayName = AppDisplayName\n |  join kind=inner\n (\n AzureActivity\n | where tolower(OperationNameValue) endswith \"listkeys/action\"\n | where ActivityStatus =~ \"Succeeded\"\n | project CallerIpAddress, _ResourceId, SubscriptionId, ActivityStatus, Category, Authorization,OperationName\n )\n on $left.IPAddress == $right. CallerIpAddress\n | project SubscriptionId, ActivityStatus, IPAddress, OperationName, UserPrincipalName\n | join kind=inner \n (\n AuditLogs\n | where LoggedByService =~ \"Core Directory\"\n | where Category =~ \"RoleManagement\"\n | extend IpAddress = case(\n  isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), \n isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),'Not Available')\n | extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \n   tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n | extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))  \n ) \n on $left. IPAddress == $right. IpAddress\n | summarize count () by TimeGenerated,IPCustomEntity=IpAddress,UserRoles,AccountCustomEntity=InitiatedBy,TargetResourceName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

