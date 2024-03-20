---
id: ea5d043f-80ef-452c-a31a-b584e485b2be
name: Insider Risk_Entity Anomaly Followed by IRM Alert
description: |
  'This query joins Microsoft Sentinel Entity Insights with Microsoft Purview Insider Risk Management Alerts. There is also an option for configuration of correlations against watchlists. For more information, see https://docs.microsoft.com/azure/sentinel/watchlists'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: OfficeATP
    dataTypes:
      - SecurityAlert (Office 365)
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078
query: "```kusto\nlet InsiderRiskManagementAlerts = SecurityAlert\n| where ProductName == \"Microsoft 365 Insider Risk Management\"\n| summarize hint.strategy = shuffle arg_max(TimeGenerated, *), NumberOfUpdates = count() by SystemAlertId\n| mv-expand todynamic(Entities)\n| where Entities[\"Type\"] =~ \"account\"\n| extend Name = tostring(tolower(Entities[\"Name\"])), NTDomain = tostring(Entities[\"NTDomain\"]), UPNSuffix = tostring(Entities[\"UPNSuffix\"]), AadUserId = tostring(Entities[\"AadUserId\"]), AadTenantId = tostring(Entities[\"AadTenantId\"]), \n          Sid = tostring(Entities[\"Sid\"]), IsDomainJoined = tobool(Entities[\"IsDomainJoined\"]), Host = tostring(Entities[\"Host\"])\n| extend UserPrincipalName = iff(Name != \"\" and UPNSuffix != \"\", strcat(Name, \"@\", UPNSuffix), \"\")\n| extend Href_ = tostring(parse_json(ExtendedLinks)[0].Href)\n| where UserPrincipalName <> \"\"\n| summarize PreviousSecurityAlertLinks=make_set(AlertLink) by UserPrincipalName, AlertLink;\nBehaviorAnalytics\n| where UserPrincipalName <> \"\"\n| where ActivityInsights contains \"True\"\n| extend EntityAnomalies = strcat(ActivityInsights)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by UserPrincipalName, EntityAnomalies\n| join kind=innerunique (InsiderRiskManagementAlerts) on UserPrincipalName\n| project UserPrincipalName, EntityAnomalies, StartTime, EndTime, AlertLink, PreviousSecurityAlertLinks\n// | lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey\n| extend AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountCustomEntity
---

