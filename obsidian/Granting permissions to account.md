---
id: 860cda84-765b-4273-af44-958b7cca85f7
name: Granting permissions to account
description: |
  'Shows the most prevalent users who grant access to others on Azure resources. List the common source IP address for each of those accounts. If an operation is not from those IP addresses, it may be worthy of investigation.'
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098
query: "```kusto\nAzureActivity\n| where OperationName =~ \"Create role assignment\"\n| where ActivityStatus =~ \"Succeeded\" \n| project Caller, CallerIpAddress\n| evaluate basket()\n// Returns all the records from the left side and only matching records from the right side.\n| join kind=leftouter (AzureActivity\n| where OperationName =~ \"Create role assignment\"\n| where ActivityStatus =~ \"Succeeded\"\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by Caller, CallerIpAddress)\non Caller, CallerIpAddress\n| project-away Caller1, CallerIpAddress1\n| where isnotempty(StartTime)\n| extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = CallerIpAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: CallerIpAddress
version: 2.0.1
---

