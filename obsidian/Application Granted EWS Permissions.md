---
id: c7941212-4ff9-4d2d-b38d-54d78fa087cc
name: Application Granted EWS Permissions
description: |
  'This query finds AD applications with EWS permissions to read user mailboxes. Threat actors could misuse these for persistent mailbox access. Ensure these permissions are legitimately granted and necessary.'
description-detailed: |
  'This query searches for AD applications granted permissions to read users mailboxes via Exchange Web Services (EWS). A threat actor could add these permissions to an application they control in order to gain persistent access to user's mail.
  Review the applications granted these permissions to ensure they are required and were granted legitimately.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
  - connectorId: AzureActiveDirectoryIdentityProtection
    dataTypes:
      - SecurityAlert (IPC)
tactics:
  - Collection
  - PrivilegeEscalation
relevantTechniques:
  - T1078.004
  - T1114.002
query: "```kusto\nAuditLogs\n| where Category =~ \"ApplicationManagement\"\n| where OperationName has \"Add app role assignment to service principal\"\n| extend UA = tostring(AdditionalDetails[0].value)\n| mv-expand TargetResources\n| extend ModifiedProps = TargetResources.modifiedProperties\n| mv-expand ModifiedProps\n| where ModifiedProps.newValue has \"Use Exchange Web Services with full access to all mailboxes\"\n| extend Action = ModifiedProps.newValue\n| extend User = tolower(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))\n| join kind=inner AuditLogs on CorrelationId\n| mv-expand TargetResources1\n| mv-expand TargetResources1.modifiedProperties\n| project-reorder TargetResources1_modifiedProperties\n| extend displayName_ = tostring(TargetResources1_modifiedProperties.displayName)\n| extend AppId = iff(tostring(TargetResources1_modifiedProperties.displayName) =~ \"ServicePrincipal.AppId\", tostring(TargetResources1_modifiedProperties.newValue), \"\")\n| extend AppName = iff(tostring(TargetResources1_modifiedProperties.displayName) =~ \"ServicePrincipal.DisplayName\", tostring(TargetResources1_modifiedProperties.newValue), \"\")\n| summarize make_set(AppName, 100), make_set(AppId, 100) by TimeGenerated, ActivityDisplayName, UA, User, Result, OperationName, tostring(InitiatedBy), bin(TimeGenerated, 1d), tostring(Action)\n| where tostring(set_AppId) != '[\"\"]'\n| project-reorder TimeGenerated, User, set_AppName\n| join kind=leftouter \n  (SecurityAlert\n    | where ProviderName =~ \"IPC\"\n    | extend User = tolower(tostring(parse_json(ExtendedProperties).[\"User Account\"]))\n    | summarize count_AlertName = count() by bin(TimeGenerated, 1d), User\n  ) on TimeGenerated, User\n| extend NumberofAADAlerts = iif(isnotempty(count_AlertName), count_AlertName, 0)\n| sort by NumberofAADAlerts desc\n| extend AppName = tostring(set_AppName[1])\n| extend AppID = tostring(set_AppId[1])\n| project-away set_AppName, set_AppId\n| project-reorder TimeGenerated, ActivityDisplayName, Action, User, NumberofAADAlerts, AppName, AppID\n| extend timestamp = TimeGenerated, UserName = tostring(split(User, '@', 0)[0]), UserUPNSuffix = tostring(split(User, '@', 1)[0])\n| extend Account_0_Name = UserName\n| extend Account_0_UPNSuffix = UserUPNSuffix\n| extend CloudApplication_0_AppId = AppID\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UserName
      - identifier: UPNSuffix
        columnName: UserUPNSuffix
  - entityType: CloudApplication
    fieldMappings:
      - identifier: AppId
        columnName: AppID
version: 1.0.1
---

