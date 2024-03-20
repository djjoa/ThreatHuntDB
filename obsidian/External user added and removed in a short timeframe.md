---
id: 119d9e1c-afcc-4d23-b239-cdb4e7bf851c
name: External user added and removed in a short timeframe
description: |
  'This hunting query identifies external user accounts that are added to a Team and then removed within one hour.'
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Teams)
tactics:
  - Persistence
relevantTechniques:
  - T1136
query: "```kusto\n// If you want to look at user added further than 7 days ago adjust this value\n// If you want to change the timeframe of how quickly accounts need to be added and removed change this value\nlet time_delta = 1h;\nOfficeActivity\n| where OfficeWorkload =~ \"MicrosoftTeams\" \n| where Operation =~ \"MemberAdded\"\n| extend UPN = tostring(parse_json(Members)[0].UPN)\n| where UPN contains (\"#EXT#\")\n| project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamName, TeamGuid\n| join kind=innerunique (\nOfficeActivity\n| where OfficeWorkload =~ \"MicrosoftTeams\" \n| where Operation =~ \"MemberRemoved\"\n| extend UPN = tostring(parse_json(Members)[0].UPN)\n| where UPN contains (\"#EXT#\")\n| project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, TeamName, TeamGuid) on UPN, TeamGuid\n| where TimeDeleted < (TimeAdded + time_delta)\n| project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName, TeamGuid\n| extend AccountName = tostring(split(UPN, \"@\")[0]), AccountUPNSuffix = tostring(split(UPN, \"@\")[1])\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
version: 2.0.1
---

