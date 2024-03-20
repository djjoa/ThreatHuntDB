---
id: dc5adcc9-70ab-4fba-8690-f57767e8ca02
name: SQL Alert Correlation with CommonSecurityLogs and AuditLogs
description: |
  'This query combines different SQL alerts with CommonSecurityLogs and AuditLogs helping analysts /investigate any possible SQL related attacks faster
   thus reducing Mean Time To Respond'
requiredDataConnectors:
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert (ASC)
  - connectorId: PaloAltoNetworks
    dataTypes:
      - CommonSecurityLog
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - InitialAccess
  - Impact
relevantTechniques:
  - T1190
  - T1078
query: "```kusto\nSecurityAlert\n| where AlertName has_any ('Potential SQL Injection', 'A possible vulnerability to SQL Injection')\n| extend EntitiesDynamicArray = parse_json(Entities)\n| mv-expand EntitiesDynamicArray\n| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address)\n| extend IpAddress = iif(EntityType == 'ip', EntityAddress, '')\n| where isnotempty(IpAddress) \n| join kind=inner (\nCommonSecurityLog \n| where DeviceVendor =~ \"Palo Alto Networks\" and Activity =~ \"TRAFFIC\" and DeviceAction != \"deny\"\n| summarize count() by DeviceName, SourceIP, DestinationIP, DestinationPort, Protocol, SourcePort\n)\non $left.IpAddress == $right.SourceIP\n| join kind=inner (\nAuditLogs\n| where LoggedByService =~ \"Core Directory\"\n| where Category =~ \"RoleManagement\"\n| extend IpAddress = case(\nisnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), \nisnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),'Not Available')\n| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \ntostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))  \n) on IpAddress\n| summarize count () by TimeGenerated,IpAddress,UserRoles,SourcePort,DestinationPort,AccountCustomEntity=InitiatedBy\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
---

