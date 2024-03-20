---
id: 61c28cd7-3139-4731-8ea7-2cbbeabb4684
name: Windows Reserved Filenames staged on Office file services
description: |
  'This identifies Windows Reserved Filenames on Office services like SharePoint and OneDrive. It also detects when a user uploads these files to another user's workspace, which may indicate malicious activity.'
description-detailed: "'Identifies when Windows Reserved Filenames show up on Office services such as SharePoint and OneDrive.\nList currently includes 'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', \n'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9' file extensions.\nAdditionally, identifies when a given user is uploading these files to another user's workspace.\nThis may be indication of a staging location for malware or other malicious activity.\nReferences: https://docs.microsoft.com/windows/win32/fileio/naming-a-file'\n"
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
tactics:
  - CommandAndControl
relevantTechniques:
  - T1105
query: "```kusto\n// Reserved FileNames/Extension for Windows\nlet Reserved = dynamic(['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']);\nOfficeActivity\n| where isnotempty(SourceFileExtension)\n| where SourceFileExtension in~ (Reserved) or SourceFileName in~ (Reserved)\n| where UserAgent !has \"Mac OS\" \n| extend SiteUrlUserFolder = tolower(split(Site_Url, '/')[-2])\n| extend UserIdUserFolderFormat = tolower(replace_regex(UserId, '@|\\\\.', '_'))\n// identify when UserId is not a match to the specific site url personal folder reference\n| extend UserIdDiffThanUserFolder = iff(Site_Url has '/personal/' and SiteUrlUserFolder != UserIdUserFolderFormat, true , false ) \n| summarize TimeGenerated = make_list(TimeGenerated, 100000), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), Operations = make_list(Operation, 100000), UserAgents = make_list(UserAgent, 100000), OfficeIds = make_list(OfficeId, 100000), SourceRelativeUrls = make_list(SourceRelativeUrl, 100000), FileNames = make_list(SourceFileName, 100000)\nby OfficeWorkload, RecordType, UserType, UserKey, UserId, ClientIP, Site_Url, SourceFileExtension,SiteUrlUserFolder, UserIdUserFolderFormat, UserIdDiffThanUserFolder\n// Use mvexpand on any list items and you can expand out the exact time and other metadata about the hit\n| extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n| extend IP_0_Address = ClientIP\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n| extend URL_0_Url = Site_Url\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Site_Url
version: 2.0.1
---

