---
id: bb3bb9da-9598-4d1f-af78-7cc2fd413b0b
name: Anomalous Sign-in Activity
description: |
  'Adversaries may steal the credentials of a specific user or service account using credential access techniques or capture credentials earlier in their reconnaissance process through social engineering as a means of gaining persistence." Umbreon, for example, creates valid users to provide access to the system.
  The query below generates an output of successful sign-in with one or more of the following indications:-
  - performed by new or recently dormant accounts
  - where one or more features of the activity deviate from the user, his peers, or the tenant's profile.
  - performed by a user with risk information from Microsoft Entra ID'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - Persistence
relevantTechniques:
  - T1078
query: "```kusto\nBehaviorAnalytics\n| where ActionType =~ \"Sign-in\"\n| where UsersInsights.IsNewAccount == True or UsersInsights.IsDormantAccount == True or ActivityInsights has \"True\"\n| join kind = inner (\nSigninLogs | where Status.errorCode == 0 or Status.errorCode == 0 and RiskDetail !~ \"none\"\n) on $left.SourceRecordId == $right._ItemId \n| extend UserPrincipalName = iff(UserPrincipalName has \"#EXT#\",replace_string(tostring(split(UserPrincipalName, \"#\")[0]),\"_\",\"@\"),UserPrincipalName),\nUserName = iff(UserName has \"#EXT#\",replace_string(tostring(split(UserPrincipalName, \"#\")[0]),\"_\",\"@\"),UserName)\n| project TimeGenerated, UserName, UserPrincipalName, UsersInsights, ActivityType, ActionType, [\"Evidence\"]=ActivityInsights, ResourceDisplayName, AppDisplayName, SourceIPAddress, SourceIPLocation, SourceDevice, DevicesInsights, ResourceId\n| extend Name=tostring(split(UserPrincipalName, \"@\")[0]), UPNSuffix=tostring(split(UserPrincipalName, \"@\")[1])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = SourceIPAddress\n| extend AzureResource_0_ResourceId = ResourceId\n```"
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

