---
id: 6f0f1821-5981-408a-930b-8b2ca60e9e6c
name: Editing Linux scheduled tasks through Crontab
description: "'This query shows when users have edited or replaced the scheduled tasks using crontab. The events are bucketed into 10 minute intervals \nand all the actions that a particular used took are collected into the List of Actions. Default query is for seven days.'\n"
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - Persistence
  - Execution
relevantTechniques:
  - T1059
  - T1053
  - T1037
query: "```kusto\n\n// Pull messages from Syslog-cron logs where the process is crontab and the severity level is \"info\". Extract the User and Action information from the SyslogMessage\nSyslog \n| where Facility =~ \"cron\" \n| where ProcessName =~ \"crontab\" \n| where SeverityLevel =~ \"info\" \n| project TimeGenerated, Computer, SeverityLevel, ProcessName, SyslogMessage\n| parse SyslogMessage with * \"(\" user  \") \" Action \" (\" *\n// Only look for messages that contain edit or replace\n| where Action contains \"EDIT\" or Action contains \"REPLACE\"\n//| summarize all the actions into a single set based on 10 minute time intervals\n| summarize ListOfActions = makeset(Action) by EventTime10MinInterval = bin(TimeGenerated, 10m), Computer, user   \n| order by Computer asc nulls last, EventTime10MinInterval asc\n| extend timestamp = EventTime10MinInterval, AccountCustomEntity = user, HostCustomEntity = Computer\n```"
---

