---
id: 0454c8d8-d0a6-42a4-8d03-f5b4fdcbd173
name: Anomalous Microsoft Entra ID Account Creation
description: |
  'Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system. The query below generates an output of all the users performing user creation where one or more features of the activity deviate from the user, his peers, or the tenant profile.'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
relevantTechniques:
  - T1136
query: |-
  ```kusto
  BehaviorAnalytics
  | where ActionType =~ "Add user"
  | where ActivityInsights has "True"
  | join kind=inner(
  AuditLogs
  ) on $left.SourceRecordId == $right._ItemId
  | mv-expand TargetResources
  | extend Target =  iff(tostring(TargetResources.userPrincipalName) has "#EXT#",replace("_","@",tostring(split(TargetResources.userPrincipalName, "#")[0])),TargetResources.userPrincipalName),tostring(TargetResources.userPrincipalName)
  | extend DisplayName = tostring(UsersInsights.AccountDisplayName),
  UserPrincipalName = iff(UserPrincipalName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserPrincipalName),
  UserName = iff(UserName has "#EXT#",replace("_","@",tostring(split(UserPrincipalName, "#")[0])),UserName)
  | sort by TimeGenerated desc	
  | project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, ["TargetUser"]=Target, ActivityInsights, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ResourceId
  | extend Name=split(UserPrincipalName, "@")[0], UPNSuffix=split(UserPrincipalName, "@")[1]
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  | extend IP_0_Address = SourceIPAddress
  | extend AzureResource_0_ResourceId = ResourceId
  ```
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
        columnName: SourceIPAddress
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
version: 2.0.0
---

