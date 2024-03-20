---
id: 09a7c5fc-0649-4f7d-a21b-36a754cef6b6
name: User Login IP Address Teleportation
description: |
  'This query identifies users logging in from two different countries within a specified time window, potentially indicating VPN use. It includes UEBA logs IdentityInfo and BehaviorAnalytics for context.'
description_detailed: |
  'This query over SiginLogs will identify user accounts that have logged in from two different countries
  within a specified time window, by default this is a 10 minute window either side of the previous login.
  This query will detect users roaming onto VPNs, it is possible to exclude known VPN IP address ranges.
  This query has also been updated to include UEBA logs IdentityInfo and BehaviorAnalytics for contextual information around the results.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
  - connectorId: BehaviorAnalytics
    dataTypes:
      - IdentityInfo
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
tags:
  - DEV-0537
query: "```kusto\n\nlet riskScoreCutoff = 20; //Adjust this based on volume of results\nlet windowTime = 20min / 2; //Window to lookup anomalous logins within\nlet excludeKnownVPN = dynamic(['127.0.0.1', '0.0.0.0']); //Known VPN IP addresses to exclude\nSigninLogs\n| where ConditionalAccessStatus =~ \"success\"\n| extend country = LocationDetails['countryOrRegion']\n| where country != \"\"\n| summarize count() by tostring(country)\n| join (\n    //Get the total number of logins from any country and join it to the previous count in a single table\n    SigninLogs\n    | where ConditionalAccessStatus =~ \"success\"\n    | extend country = LocationDetails['countryOrRegion']\n    | where country != \"\"\n    | summarize count(), make_list(tostring(country))\n    | mv-expand list_country\n    | extend country = tostring(list_country)\n) on country\n| summarize by country, count_, count_1\n//Now calculate each countries prevalence within login events\n| extend prevalence = toreal(count_) / toreal(count_1) * 100\n| project-away count_1\n| where prevalence < 0.01\n| join kind=rightsemi(\n    SigninLogs\n    //Enable to limit to o365 exchange logins\n    //| where AppDisplayName =~ \"Office 365 Exchange Online\"\n    | where ConditionalAccessStatus =~ \"success\"\n    | where IPAddress != \"\"\n    | extend country = tostring(LocationDetails['countryOrRegion'])\n    | summarize count() by TimeGenerated, UserPrincipalName, country, IPAddress\n) on country\n| join kind=leftouter (\n    SigninLogs\n    //Enable to limit to o365 exchange logins\n    //| where AppDisplayName =~ \"Office 365 Exchange Online\"\n    | where ConditionalAccessStatus =~ \"success\"\n    | extend country = tostring(LocationDetails['countryOrRegion'])\n    | summarize by TimeGenerated, IPAddress, UserPrincipalName, country\n) on UserPrincipalName\n| where IPAddress != IPAddress1 and country != country1\n| extend WindowStart = TimeGenerated1 - windowTime\n| extend WindowEnd = TimeGenerated1 + windowTime\n| where TimeGenerated between (WindowStart .. WindowEnd)\n| project Account=UserPrincipalName, AnomalousIP=IPAddress, AnomalousLoginTime=TimeGenerated, AnomalousCountry=country, OtherLoginIP=IPAddress1, OtherLoginCountry=country1, OtherLoginWindowStart=WindowStart, OtherLoginWindowEnd=WindowEnd\n| where AnomalousIP !in(excludeKnownVPN) and OtherLoginIP !in(excludeKnownVPN)\n| extend timestamp = AnomalousLoginTime, Account = tolower(Account), Account_0_Name = Account, IP_0_Address = AnomalousIP\n| join kind=leftouter (\n    IdentityInfo\n    | summarize LatestReportTime = arg_max(TimeGenerated, *) by AccountUPN\n    | extend BlastRadiusInt = iif(BlastRadius == \"High\", 1, 0)\n    | project AccountUPN, Tags, JobTitle, GroupMembership, AssignedRoles, UserType, IsAccountEnabled, BlastRadiusInt\n    | summarize\n        Tags = make_set(Tags, 1000),\n        GroupMembership = make_set(GroupMembership, 1000),\n        AssignedRoles = make_set(AssignedRoles, 1000),\n        BlastRadiusInt = sum(BlastRadiusInt),\n        UserType = make_set(UserType, 1000),\n        UserAccountControl = make_set(UserType, 1000)\n    by AccountUPN\n    | extend UserPrincipalName=tolower(AccountUPN)\n    | project-rename Account = AccountUPN\n) on Account\n| join kind=leftouter (\n    BehaviorAnalytics\n    | where ActivityType in (\"FailedLogOn\", \"LogOn\")\n    | where isnotempty(SourceIPAddress)\n    | project UsersInsights, DevicesInsights, ActivityInsights, InvestigationPriority, SourceIPAddress\n    | project-rename AnomalousIP = SourceIPAddress\n    | summarize\n        UsersInsights = make_set(UsersInsights, 1000),\n        DevicesInsights = make_set(DevicesInsights, 1000),\n        IPInvestigationPriority = sum(InvestigationPriority)\n    by AnomalousIP)\non AnomalousIP\n| extend UEBARiskScore = BlastRadiusInt + IPInvestigationPriority\n| where  UEBARiskScore > riskScoreCutoff\n| sort by UEBARiskScore desc \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Account
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: AnomalousIP
version: 2.0.1
---

