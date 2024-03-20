---
id: eb09da09-6f6c-4502-bf74-f7b9f1343539
name: Linux scheduled task Aggregation
description: |
  'This query aggregates information about all of the scheduled tasks (Cron jobs) and presents the data in a chart.
  The aggregation is done based on unique user-commandline pairs. It returns how many times a command line has
  been run from a particular user, how many computers that pair has run on, and what percentage that is of the
  total number of computers in the tenant.'
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
query: "```kusto\n\n// Pull messages from Syslog-cron where the process name is \"CRON\" or \"CROND\", the severity level is info, and the SyslogMessage contains \"CMD\".\n// It also parses out the user and commandline from the message.\nlet RawCommands = Syslog \n| where Facility =~ \"cron\" \n| where SeverityLevel =~ \"info\" \n| where ProcessName =~ \"CRON\" or ProcessName =~ \"CROND\"  \n| where SyslogMessage contains \"CMD \" \n| project TenantId, TimeGenerated, Computer, SeverityLevel, ProcessName, SyslogMessage\n| extend TrimmedSyslogMsg = trim_end(@\"\\)\", SyslogMessage)\n| parse TrimmedSyslogMsg with * \"(\" user  \") CMD (\" cmdline \n| project TenantId, TimeGenerated, Computer, user, cmdline; \n// Count how many times a particular commandline has been seen based on unique Computer, User, and cmdline sets\nlet CommandCount = RawCommands\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), CmdlineCount = count() by Computer, user, cmdline; \n// Count how many computers have run a particular user and cmdline pair\nlet DistComputerCount = RawCommands\n| summarize ComputerCount = dcount(Computer) by TenantId, user, cmdline; \n// Join above counts based on user and commandline pair\nlet CommandSummary = CommandCount | join (DistComputerCount) on user, cmdline\n| project StartTime, EndTime, TenantId, user, CmdlineCount, ComputerCount, cmdline;\n// Count the total number of computers reporting cron messages in the tenant\nlet TotalComputers = Syslog\n| where Facility =~ \"cron\"\n| summarize dcount(Computer) by TenantId ;\n// Join the previous counts with the total computers count. Calculate the percentage of total computers value.\nlet FinalSummary = CommandSummary | join kind= leftouter (TotalComputers) on TenantId\n| project StartTime, EndTime, user, TimesCmdlineSeen = CmdlineCount, CompsThatHaveRunCmdline = ComputerCount, \nAsPercentOfTotalComps = round(100 * (toreal(ComputerCount)/toreal(dcount_Computer)),2), cmdline\n| order by user asc, TimesCmdlineSeen desc;\nFinalSummary \n| extend timestamp = StartTime, AccountCustomEntity = user\n```"
---

