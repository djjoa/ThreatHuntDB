---
id: 3a0447c1-7f43-43d0-aeac-d5e1247964a8
name: Administrators Authenticating to Another Microsoft Entra ID Tenant
description: |
  'Detects when a privileged user account successfully authenticates from to another Microsoft Entra ID Tenant.
    Authentication attempts should be investigated to ensure the activity was legitimate and if there is other similar activity.
    Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-successful-unusual-sign-ins'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - IdentityInfo
tactics:
  - InitialAccess
relevantTechniques:
  - T1078.004
query: |-
  ```kusto
  let admin_users = (IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | where AssignedRoles contains "admin"
    | summarize by tolower(AccountUPN));
    SigninLogs
    | where TimeGenerated between(ago(14d)..ago(1d))
    | where ResultType == 0
    | where tolower(UserPrincipalName) in (admin_users)
    | where HomeTenantId != ResourceTenantId
    | summarize by UserPrincipalName, ResourceTenantId
    | join kind=rightanti (SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | where tolower(UserPrincipalName) in (admin_users)
    | where HomeTenantId != ResourceTenantId
    | where isnotempty(HomeTenantId) and isnotempty(ResourceTenantId)) on UserPrincipalName, ResourceTenantId
    | where RiskLevelAggregated != "none"
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
version: 1.0.1
---

