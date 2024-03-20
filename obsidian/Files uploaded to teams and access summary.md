---
id: 90e198a9-efb6-4719-ad89-81b8e93633a7
name: Files uploaded to teams and access summary
description: "'This hunting queries identifies files uploaded to SharePoint via a Teams chat and\nsummarizes users and IP addresses that have accessed these files. This allows for \nidentification of anomolous file sharing patterns.'\n"
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (SharePoint)
tactics:
  - InitialAccess
  - Exfiltration
relevantTechniques:
  - T1199
  - T1102
  - T1078
query: "```kusto\nOfficeActivity \n| where RecordType =~ \"SharePointFileOperation\"\n| where Operation =~ \"FileUploaded\" \n| where UserId != \"app@sharepoint\"\n| where SourceRelativeUrl has \"Microsoft Teams Chat Files\" \n| join kind= leftouter ( \n   OfficeActivity \n    | where RecordType =~ \"SharePointFileOperation\"\n    | where Operation =~ \"FileDownloaded\" or Operation =~ \"FileAccessed\" \n    | where UserId != \"app@sharepoint\"\n    | where SourceRelativeUrl has \"Microsoft Teams Chat Files\" \n) on OfficeObjectId \n| extend userBag = bag_pack(UserId1, ClientIP1) \n| summarize make_set(UserId1, 10000), make_bag(userBag, 10000) by TimeGenerated, UserId, OfficeObjectId, SourceFileName \n| extend NumberUsers = array_length(bag_keys(bag_userBag))\n| project timestamp=TimeGenerated, UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, NumberOfUsersAccessed=NumberUsers\n| extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
version: 2.0.1
---

