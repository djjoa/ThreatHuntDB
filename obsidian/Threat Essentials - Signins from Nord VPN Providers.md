---
id: 1eaad895-7796-466b-8bf3-cec0fa78d0e4
name: Threat Essentials - Signins from Nord VPN Providers
description: |
  'This query looks for sign-in activity from NordVPN providers using the public feed leveraging the NordVPN API. Investigation of any unknown sign-in attempts from VPN providers such as Nord VPN unless it is commonly seen from users in the organization'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
tags:
  - DEV-0537
query: "```kusto\nlet nord_vpn_feed = (externaldata(id:int,ip_address: string,search_keywords: dynamic,categories:dynamic,name: string,domain:string,price:int,flag:string,country:string,location:dynamic ,load: int ,features:dynamic)\n  [@\"https://raw.githubusercontent.com/microsoft/mstic/master/nordvpn-servers.csv\"] with (format=\"csv\", ignoreFirstRecord=True));\nSigninLogs\n  | where ResultType == 0 \n  | summarize TotalEvents = count(), AppList = make_set(AppDisplayName,100),  StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by IPAddress, UserPrincipalName, ClientAppUsed, ConditionalAccessStatus, AuthenticationRequirement, RiskDetail \n  | join kind= inner nord_vpn_feed on $left.IPAddress == $right.ip_address\n  | project StartTime , EndTime, IPAddress, UserPrincipalName, AppList, ClientAppUsed, ConditionalAccessStatus, AuthenticationRequirement, RiskDetail, categories, domain, country\n  | extend Name = tostring(split(UserPrincipalName,'@',0)[0]), UPNSuffix = tostring(split(UserPrincipalName,'@',1)[0])\n  | extend Account_0_Name = Name\n  | extend Account_0_UPNSuffix = UPNSuffix\n  | extend IP_0_Address = IPAddress\n```"
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
        columnName: IPAddress
version: 2.0.1
---

