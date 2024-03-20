---
id: d12580c2-1474-4125-a8a3-553f50d91215
name: Exes with double file extension and access summary
description: "'Provides a summary of executable files with double file extensions in SharePoint \n and the users and IP addresses that have accessed them.'\n"
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (SharePoint)
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1036
query: "```kusto\nlet known_ext = dynamic([\"lnk\",\"log\",\"option\",\"config\", \"manifest\", \"partial\"]);\nlet excluded_users = dynamic([\"app@sharepoint\"]);\nOfficeActivity\n| where RecordType =~ \"SharePointFileOperation\" and isnotempty(SourceFileName)\n| where OfficeObjectId has \".exe.\" and SourceFileExtension !in~ (known_ext)\n| extend Extension = extract(\"[^.]*.[^.]*$\",0, OfficeObjectId)\n| join kind= leftouter ( \n  OfficeActivity\n    | where RecordType =~ \"SharePointFileOperation\" and (Operation =~ \"FileDownloaded\" or Operation =~ \"FileAccessed\") \n    | where SourceFileExtension !in~ (known_ext)\n) on OfficeObjectId \n| where UserId1 !in~ (excluded_users)\n| extend userBag = bag_pack(UserId1, ClientIP1) \n| summarize make_set(UserId1, 10000), make_bag(userBag), Start=max(TimeGenerated), End=min(TimeGenerated) by UserId, OfficeObjectId, SourceFileName, Extension \n| extend NumberOfUsers = array_length(bag_keys(bag_userBag))\n| project UploadTime=Start, Uploader=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, Extension, NumberOfUsers\n| extend UploaderName = tostring(split(Uploader, \"@\")[0]), UploaderUPNSuffix = tostring(split(Uploader, \"@\")[1])\n| extend Account_0_Name = UploaderName\n| extend Account_0_UPNSuffix = UploaderUPNSuffix\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: UploaderName
      - identifier: UPNSuffix
        columnName: UploaderUPNSuffix
version: 2.0.1
---

