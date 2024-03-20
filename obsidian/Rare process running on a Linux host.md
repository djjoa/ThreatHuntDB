---
id: d0ae35df-0eaf-491f-b23e-8190e4f3ffe9
name: Rare process running on a Linux host
description: |
  'Looks for rare processes that are running on Linux hosts. Looks for process seen less than 14 times in last 7 days,
   or observed rate is less than 1% of of the average for the environment and fewer than 100.'
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - Execution
  - Persistence
relevantTechniques:
  - T1059
  - T1053
  - T1037
query: "```kusto\n\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 14d;\nlet count_threshold = 100;\nlet perc_threshold = 0.01;\nlet host_threshold = 14;\nlet basic=materialize(\nSyslog | where TimeGenerated >= lookback\n| summarize FullCount = count(), Count= countif(TimeGenerated between (starttime .. endtime)), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) \nby Computer, ProcessName\n| where Count > 0 and Count < count_threshold);\nlet basic_avg = basic\n| summarize Avg = avg(FullCount) by  ProcessName;\nbasic | project-away FullCount\n| join kind=inner\nbasic_avg\non ProcessName | project-away ProcessName1\n| where Count < host_threshold or (Count <= Avg*perc_threshold and Count < count_threshold)\n| extend timestamp = StartTime, HostCustomEntity=Computer\n```"
---

