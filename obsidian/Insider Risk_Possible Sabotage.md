---
id: 3201b17a-06e1-4a8d-8157-c69345baa808
name: Insider Risk_Possible Sabotage
description: |
  'This query correlates users with entity anomalies, security alerts, and delete/remove actions for identification of possible sabotage activities (watchlists configurable). For more information, see https://docs.microsoft.com/azure/sentinel/watchlists'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: MicrosoftDefenderAdvancedThreatProtection
    dataTypes:
      - SecurityAlert (MDATP)
  - connectorId: AzureActiveDirectoryIdentityProtection
    dataTypes:
      - SecurityAlert (IPC)
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert (ASC)
  - connectorId: IoT
    dataTypes:
      - SecurityAlert (ASC for IoT)
  - connectorId: MicrosoftCloudAppSecurity
    dataTypes:
      - SecurityAlert (ASC for IoT)
  - connectorId: IoT
    dataTypes:
      - SecurityAlert (MCAS)
  - connectorId: OfficeATP
    dataTypes:
      - SecurityAlert (Office 365)
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Impact
relevantTechniques:
  - T1485
query: "```kusto\nlet RemoveActions = AzureActivity\n| where OperationName contains \"delete\" or OperationName contains \"remove\"\n| extend UserPrincipalName = Caller\n| project UserPrincipalName, OperationName, Category, Resource, ResourceId, ActivityStatus, TimeGenerated;\nlet InsiderRiskManagementAlerts = SecurityAlert\n| summarize hint.strategy = shuffle arg_max(TimeGenerated, *), NumberOfUpdates = count() by SystemAlertId\n| mv-expand todynamic(Entities)\n| where Entities[\"Type\"] =~ \"account\"\n| extend Name = tostring(tolower(Entities[\"Name\"])), NTDomain = tostring(Entities[\"NTDomain\"]), UPNSuffix = tostring(Entities[\"UPNSuffix\"]), AadUserId = tostring(Entities[\"AadUserId\"]), AadTenantId = tostring(Entities[\"AadTenantId\"]), \n          Sid = tostring(Entities[\"Sid\"]), IsDomainJoined = tobool(Entities[\"IsDomainJoined\"]), Host = tostring(Entities[\"Host\"])\n| extend UserPrincipalName = iff(Name != \"\" and UPNSuffix != \"\", strcat(Name, \"@\", UPNSuffix), \"\")\n| extend Href_ = tostring(parse_json(ExtendedLinks)[0].Href)\n| where UserPrincipalName <> \"\"\n| summarize PreviousSecurityAlertLinks=make_set(AlertLink) by UserPrincipalName, AlertLink, AlertName;\nBehaviorAnalytics\n| where UserPrincipalName <> \"\"\n| where ActivityInsights contains \"True\"\n| extend EntityAnomalies = strcat(ActivityInsights)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, EntityAnomalies\n| join kind=innerunique (InsiderRiskManagementAlerts) on UserPrincipalName\n| join kind=innerunique (RemoveActions) on UserPrincipalName\n| project UserPrincipalName, EntityAnomalies, AlertName, AlertLink, PreviousSecurityAlertLinks, OperationName, Category, Resource, ResourceId, ActivityStatus, TimeGenerated\n//| lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey\n| sort by TimeGenerated desc\n| limit 50\n| extend AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountCustomEntity
---

