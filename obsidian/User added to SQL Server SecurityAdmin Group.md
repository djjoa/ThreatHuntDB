---
id: 363ea6d1-b30d-4a44-b56a-63c3c8a99621
name: User added to SQL Server SecurityAdmin Group
description: |
  This hunting query identifies user added in the SecurityAdmin group of SQL Server
  This query is based on the SQLEvent KQL Parser function (link below)
  SQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSever
  Detailed blog post on Monitoring SQL Server with Microsoft Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960
requiredDataConnectors:
  - connectorId: AzureMonitor(WindowsEventLogs)
    dataTypes:
      - Event
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098
  - T1078
query: "```kusto\n// SQLEvent is not the table name, it is the function name that should already be imported into your workspace.\n// The underlying table where the data exists is the Event table.\n// This query tracks user added into SecurityAdmingroup\nSQLEvent\n| where Statement has_all (\"Alter Server role\", \"add member\")\n| parse Statement with * \"ADD MEMBER [\" TargetUser:string \"]\" *\n| where ObjectName has \"securityadmin\"\n| project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement \n| extend Name = iff(CurrentUser contains '@', tostring(split(CurrentUser, '@', 0)[0]), CurrentUser)\n| extend UPNSuffix = iff(CurrentUser contains '@', tostring(split(CurrentUser, '@', 1)[0]), '')\n| extend Name = iff(CurrentUser contains '\\\\', tostring(split(CurrentUser, '\\\\', 1)[0]), Name)\n| extend NTDomain = iff(CurrentUser contains '\\\\', tostring(split(CurrentUser, '\\\\', 0)[0]), '')\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Account_0_NTDomain = NTDomain\n| extend IP_0_Address = ClientIP\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
version: 2.0.0
---

