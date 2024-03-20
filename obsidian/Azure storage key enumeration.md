---
id: 5d2399f9-ea5c-4e67-9435-1fba745f3a39
name: Azure storage key enumeration
description: |
  'Azure's storage key listing can expose secrets, PII, and grant VM access. Monitoring for anomalous accounts or IPs is crucial. The query generates IP clusters, correlates activities, and flags unexpected ones. Single-operation users are excluded.'
description_detailed: "'Listing of storage keys is an interesting operation in Azure which might expose additional \nsecrets and PII to callers as well as granting access to VMs. While there are many benign operations of this\ntype, it would be interesting to see if the account performing this activity or the source IP address from \nwhich it is being done is anomalous. \nThe query below generates known clusters of ip address per caller, notice that users which only had single\noperations do not appear in this list as we cannot learn from it their normal activity (only based on a single\nevent). The activities for listing storage account keys is correlated with this learned \nclusters of expected activities and activity which is not expected is returned.'\n"
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Discovery
relevantTechniques:
  - T1087
query: "```kusto\nAzureActivity\n| where OperationNameValue =~ \"microsoft.storage/storageaccounts/listkeys/action\"\n| where ActivityStatusValue =~ \"Succeeded\" \n| join kind= inner (\n    AzureActivity\n    | where OperationNameValue =~ \"microsoft.storage/storageaccounts/listkeys/action\"\n    | where ActivityStatusValue =~ \"Succeeded\" \n    | project ExpectedIpAddress=CallerIpAddress, Caller \n    | evaluate autocluster()\n) on Caller\n| where CallerIpAddress != ExpectedIpAddress\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), ResourceIds = make_set(ResourceId,100), ResourceIdCount = dcount(ResourceId) by OperationNameValue, Caller, CallerIpAddress\n| extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend IP_0_Address = CallerIpAddress\n```"
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

