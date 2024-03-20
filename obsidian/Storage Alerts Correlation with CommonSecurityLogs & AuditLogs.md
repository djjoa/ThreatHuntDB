---
id: 860a8df2-8d19-4c60-bf61-de1c02422797
name: Storage Alerts Correlation with CommonSecurityLogs & AuditLogs
description: |
  'This query combines different Storage alerts with CommonSecurityLogs and AuditLogs helping analysts investigate any possible storage related attacks faster
   thus reducing Mean Time To Respond'
requiredDataConnectors:
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert (ASC)
  - connectorId: Fortinet
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
query: "```kusto\nSecurityAlert\n| where AlertName has_any ('Access from  a suspicious IP to a storage file share','\tAccess from a Tor exit node to a storage blob container')\n| extend EntitiesDynamicArray = parse_json(Entities) | mv-expand EntitiesDynamicArray\n// Parsing relevant entity column extract hostname and IP address\n| extend EntityType = tostring(parse_json(EntitiesDynamicArray).Type), EntityAddress = tostring(EntitiesDynamicArray.Address)\n| extend IpAddress = iif(EntityType == 'ip', EntityAddress, '')\n| where isnotempty(IpAddress) \n| join kind=inner (\nCommonSecurityLog \n| where DeviceVendor =~ \"Fortinet\"\n| where ApplicationProtocol has_any (\"SSL\",\"RDP\")\n| where LogSeverity has_any (\"2\",\"3\")\n| where isnotempty(SourceIP) and isnotempty(DestinationIP) and SourceIP != \"0.0.0.0\"\n| where DeviceAction !in (\"close\", \"client-rst\", \"server-rst\", \"deny\") and DestinationPort != 161\n| project DeviceProduct,LogSeverity,DestinationPort,DestinationIP,Message,SourceIP,SourcePort,Activity,SentBytes,ReceivedBytes\n) on $left.IpAddress == $right.DestinationIP\n| join kind=inner (\nAuditLogs\n| where LoggedByService =~ \"Core Directory\"\n| where Category =~ \"RoleManagement\"\n| extend IpAddress = case(\nisnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), \nisnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),\n'Not Available')\n| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \ntostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName)) \n)\non IpAddress\n| summarize count () by TimeGenerated,IpAddress, UserRoles,SourcePort, DestinationPort, AccountCustomEntity =InitiatedBy\n```"
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

