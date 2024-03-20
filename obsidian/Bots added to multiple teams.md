---
id: 9eb64924-ec8d-44d0-b1f2-10665150fb74
name: Bots added to multiple teams
description: |
  'This hunting query helps identify bots added to multiple Teams in a short space of time.'
requiredDataConnectors:
  - connectorId: Office365
    dataTypes:
      - OfficeActivity (Teams)
tactics:
  - Persistence
  - Collection
relevantTechniques:
  - T1176
  - T1119
query: "```kusto\n// Adjust these thresholds to suit your environment.\nlet threshold = 2;\nlet time_threshold = timespan(5m);\nOfficeActivity\n  | where OfficeWorkload =~ \"MicrosoftTeams\"\n  | where Operation =~ \"BotAddedToTeam\"\n  | summarize Start=max(TimeGenerated), End=min(TimeGenerated), Teams = make_set(TeamName, 10000) by UserId\n  | extend CountOfTeams = array_length(Teams)\n  | extend TimeDelta = End - Start \n  | where CountOfTeams > threshold\n  | where TimeDelta >= time_threshold\n  | project Start, End, Teams, CountOfTeams, UserId\n  | extend AccountName = tostring(split(UserId, \"@\")[0]), AccountUPNSuffix = tostring(split(UserId, \"@\")[1])\n  | extend Account_0_Name = AccountName\n  | extend Account_0_UPNSuffix = AccountUPNSuffix\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountName
      - identifier: UPNSuffix
        columnName: AccountUPNSuffix
version: 2.0.1
---

