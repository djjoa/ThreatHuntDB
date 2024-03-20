---
id: 82e04ff9-a289-4005-9fcd-f1deec72e3fc
name: Hosts Running a Rare Process
description: |
  This query searches for hosts running a rare process. A rare process has execution requency of less than 1% of the average for 30 days and less than a count of 100 on a given host or less than a 14 count on a given host from the last 7 days.
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Execution
  - Persistence
  - Discovery
  - LateralMovement
  - Collection
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 30d;\nlet basic=materialize(\n  SecurityEvent\n    | where TimeGenerated between(lookback..endtime)\n    | where EventID == 4688\n    | summarize FullCount = count()\n                , Count= countif(TimeGenerated between (starttime .. endtime))\n                , min_TimeGenerated=min(TimeGenerated)\n                , max_TimeGenerated=max(TimeGenerated)\n                      by Computer, NewProcessName\n    | where Count > 0 and Count < 100);\nlet basic_avg = basic\n    | summarize Avg = avg(FullCount) by  NewProcessName;\nbasic | project-away FullCount\n  | join kind=inner\nbasic_avg\n  on NewProcessName | project-away NewProcessName1\n  | where Count < 14 or (Count <= Avg*0.01 and Count < 100)\n  | extend HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n  | extend Host_0_HostName = HostName\n  | extend Host_0_DnsDomain = DnsDomain \n```"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.1
---

