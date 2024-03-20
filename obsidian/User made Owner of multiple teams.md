---
id: 558f15dd-3171-4b11-bf24-31c0610a20e0
name: User made Owner of multiple teams
description: |
  'This hunting query identifies users who have been made Owner of multiple Teams.'
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Teams)
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078
query: "```kusto\n// Adjust this value to change how many teams a user is made owner of before detecting\nlet max_owner_count = 3;\n// Change this value to adjust how larger timeframe the query is run over.\nlet high_owner_count = (OfficeActivity\n| where OfficeWorkload =~ \"MicrosoftTeams\"\n| where Operation =~ \"MemberRoleChanged\"\n| extend Member = tostring(parse_json(Members)[0].UPN) \n| extend NewRole = toint(parse_json(Members)[0].Role) \n| where NewRole == 2\n| summarize dcount(TeamName) by Member\n| where dcount_TeamName > max_owner_count\n| project Member);\nOfficeActivity\n| where OfficeWorkload =~ \"MicrosoftTeams\"\n| where Operation =~ \"MemberRoleChanged\"\n| extend Member = tostring(parse_json(Members)[0].UPN) \n| extend NewRole = toint(parse_json(Members)[0].Role) \n| where NewRole == 2\n| where Member in (high_owner_count)\n| extend AccountName = tostring(split(Member, \"@\")[0]), AccountUPNSuffix = tostring(split(Member, \"@\")[1])\n| extend Account_0_Name = AccountName\n| extend Account_0_UPNSuffix = AccountUPNSuffix\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
version: 2.0.1
---

