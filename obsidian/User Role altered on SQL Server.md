---
id: 80a420b3-6a97-4b8f-9d86-4b43ee522fb2
name: User Role altered on SQL Server
description: "This hunting query identifies user role altered on SQL Server\nThis query is based on the SQLEvent KQL Parser function (link below) \nSQLEvent KQL Parser provided at https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/SQLSever\nDetailed blog post on Monitoring SQL Server with Microsoft Sentinel https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/ba-p/1502960\n"
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
query: |-
  ```kusto
  // SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
  // The underlying table where the data exists is the Event table.
  // This query looking for Alter role commands and extracts username which was altered and target objectName
  SQLEvent
  | where Statement has_all ("Alter role", "add member")
  | parse Statement with * "ADD MEMBER [" TargetUser:string "]" *
  | project TimeGenerated, Computer, Action, ClientIP, CurrentUser, DatabaseName, TargetUser, ObjectName, Statement
  | extend Name = iff(CurrentUser contains '@', tostring(split(CurrentUser, '@', 0)[0]), CurrentUser)
  | extend UPNSuffix = iff(CurrentUser contains '@', tostring(split(CurrentUser, '@', 1)[0]), '')
  | extend Name = iff(CurrentUser contains '\\', tostring(split(CurrentUser, '\\', 1)[0]), Name)
  | extend NTDomain = iff(CurrentUser contains '\\', tostring(split(CurrentUser, '\\', 0)[0]), '')
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend Account_0_NTDomain = NTDomain
  | extend IP_0_Address = ClientIP
  ```
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
