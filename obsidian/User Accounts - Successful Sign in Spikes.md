---
id: 3c7fcea1-ec9f-4ea2-a555-156073b2d183
name: User Accounts - Successful Sign in Spikes
description: |
  ' Identifies measureable increase in successful sign-ins from user accounts.
  Spike is determined based on Time series anomaly which will look at historical baseline values.
  Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-successful-unusual-sign-ins'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AADNonInteractiveUserSignInLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078.004
tags:
  - AADSecOpsGuide
query: "```kusto\nlet starttime = 14d;\nlet timeframe = 1d;\nlet scorethreshold = 5;\nlet baselinethreshold = 25;\nlet aadFunc = (tableName:string){\n  // Succesful signins.\n  table(tableName)\n  | where TimeGenerated between (startofday(ago(starttime))..startofday(ago(timeframe)))\n  | where ResultType == 0\n  | extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName\n};\nlet aadSignin = aadFunc(\"SigninLogs\");\nlet aadNonInt = aadFunc(\"AADNonInteractiveUserSignInLogs\");\nlet allSignins = union isfuzzy=true aadSignin, aadNonInt ;\nlet TimeSeriesData = union isfuzzy=true aadSignin, aadNonInt \n| project TimeGenerated, UserPrincipalName\n| make-series HourlyCount=count() on TimeGenerated from startofday(ago(starttime)) to startofday(now()) step timeframe by UserPrincipalName\n| project  TimeGenerated, UserPrincipalName, HourlyCount;\nlet TimeSeriesAlerts = TimeSeriesData\n| extend (anomalies, score, baseline) = series_decompose_anomalies(HourlyCount, scorethreshold, -1, 'linefit')\n| mv-expand HourlyCount to typeof(double), TimeGenerated to typeof(datetime), anomalies to typeof(double),score to typeof(double), baseline to typeof(long)\n| where anomalies > 0 | extend AnomalyHour = TimeGenerated\n| where baseline > baselinethreshold // Filtering low count events per baselinethreshold\n| project UserPrincipalName, AnomalyHour, TimeGenerated, HourlyCount, baseline, anomalies, score;\nlet AnomalyHours = TimeSeriesAlerts | where TimeGenerated > ago(2d) | project TimeGenerated;\n// Filter the alerts for specified timeframe\nTimeSeriesAlerts\n| where TimeGenerated > ago(2d)\n| join kind=inner ( \nunion isfuzzy=true aadSignin, aadNonInt\n| where TimeGenerated > ago(2d)\n| extend DateHour = bin(TimeGenerated, 1h) // create a new column and round to hour\n| where DateHour in ((AnomalyHours)) //filter the dataset to only selected anomaly hours\n | summarize HourlyCount=count(), LatestAnomalyTime = arg_max(timestamp,*) by bin(TimeGenerated,1h),  OperationName, Category, ResultType, ResultDescription, UserPrincipalName, UserDisplayName, AppDisplayName, ClientAppUsed, IPAddress, ResourceDisplayName\n) on UserPrincipalName\n| project LatestAnomalyTime,  OperationName, Category, UserPrincipalName, UserDisplayName, ResultType, ResultDescription, AppDisplayName, ClientAppUsed, UserAgent, IPAddress, Location, AuthenticationRequirement, ConditionalAccessStatus, ResourceDisplayName, HourlyCount, baseline, anomalies, score\n| extend timestamp = LatestAnomalyTime, IPCustomEntity = IPAddress, AccountCustomEntity = UserPrincipalName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

