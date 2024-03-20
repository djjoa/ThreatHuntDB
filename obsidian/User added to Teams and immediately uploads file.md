---
id: 3d6d0c04-7337-40cf-ace6-c471d442356d
name: User added to Teams and immediately uploads file
description: |
  'This hunting queries identifies users who are added to a Teams Channel or Teams chat
  and within 1 minute of being added upload a file via the chat. This might be
  an indicator of suspicious activity.'
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Teams)
tactics:
  - InitialAccess
relevantTechniques:
  - T1566
query: "```kusto\nlet threshold = 1m;\nOfficeActivity\n| where OfficeWorkload =~ \"MicrosoftTeams\"\n| where Operation == \"MemberAdded\"\n| extend TeamName = iff(isempty(TeamName), Members[0].UPN, TeamName)\n| project TimeGenerated, UploaderID=UserId, TeamName\n| join (\n  OfficeActivity\n  | where RecordType == \"SharePointFileOperation\"\n  | where SourceRelativeUrl has \"Microsoft Teams Chat Files\"\n  | where Operation == \"FileUploaded\"\n  | project UploadTime=TimeGenerated, UploaderID=UserId, FileLocation=OfficeObjectId, FileName=SourceFileName\n  ) on UploaderID\n| where UploadTime > TimeGenerated and UploadTime < TimeGenerated+threshold\n| project-away UploaderID1\n| extend timestamp=TimeGenerated, AccountCustomEntity = UploaderID \n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
version: 2.0.1
---

