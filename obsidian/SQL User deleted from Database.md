---
id: 7b8fa5f5-4f5b-4698-a4cf-720bbb215bea
name: SQL User deleted from Database
description: |
  This hunting query identifies deletion of user from SQL Database
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
  - Impact
relevantTechniques:
  - T1098
  - T1078
  - T1496
query: |-
  ```kusto
  // SQLEvent is not the table name, it is the function name that should already be imported into your workspace.
  // The underlying table where the data exists is the Event table.
  // This query checks for user removed from a database by parsing the statement field at the query time.
  //
  SQLEvent
  | where Statement has_all ("Alter role", "drop member")
  | parse Statement with * "DROP MEMBER [" TargetUser:string "]" *
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

