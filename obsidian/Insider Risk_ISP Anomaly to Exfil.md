---
id: 12b6582f-b715-4f91-98e1-1582ebad348a
name: Insider Risk_ISP Anomaly to Exfil
description: |
  'This query joins UEBA to Security Alerts from Microsoft products for a correlation of Internet Service Provider anomalies to data exfiltration (watchlist options). For more information, see https://docs.microsoft.com/azure/sentinel/watchlists'
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
tactics:
  - Exfiltration
relevantTechniques:
  - T1567
query: "```kusto\nlet ExfiltrationAlerts = SecurityAlert\n| summarize hint.strategy = shuffle arg_max(TimeGenerated, *), NumberOfUpdates = count() by SystemAlertId\n| mv-expand todynamic(Entities)\n| where Entities[\"Type\"] =~ \"account\"\n| extend Name = tostring(tolower(Entities[\"Name\"])), NTDomain = tostring(Entities[\"NTDomain\"]), UPNSuffix = tostring(Entities[\"UPNSuffix\"]), AadUserId = tostring(Entities[\"AadUserId\"]), AadTenantId = tostring(Entities[\"AadTenantId\"]), \n          Sid = tostring(Entities[\"Sid\"]), IsDomainJoined = tobool(Entities[\"IsDomainJoined\"]), Host = tostring(Entities[\"Host\"])\n| extend UserPrincipalName = iff(Name != \"\" and UPNSuffix != \"\", strcat(Name, \"@\", UPNSuffix), \"\")\n| extend Href_ = tostring(parse_json(ExtendedLinks)[0].Href)\n| where UserPrincipalName <> \"\"\n| where Tactics contains \"exfiltration\"\n| summarize PreviousSecurityAlertLinks=make_set(AlertLink) by UserPrincipalName, AlertName, TimeGenerated\n| where PreviousSecurityAlertLinks contains \"https\";\nBehaviorAnalytics\n| where ActivityInsights contains \"ISP\"\n| extend ISPAnomalies = strcat(ActivityInsights)\n| join kind=innerunique(ExfiltrationAlerts) on UserPrincipalName\n// | lookup kind=inner _GetWatchlist('<Your Watchlist Name>') on $left.UserPrincipalName == $right.SearchKey\n| project UserPrincipalName, AlertName, PreviousSecurityAlertLinks, ISPAnomalies, TimeGenerated\n| sort by TimeGenerated desc\n| limit 25\n| extend AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AccountCustomEntity
---

