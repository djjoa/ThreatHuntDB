---
id: 528c1708-a67e-4e2f-b76d-d5e5e88a22aa
name: Login spike with increase failure rate
description: |
  'Query over SigninLogs summarizes login attempts per hour on weekdays. Kusto anomaly detection finds login spikes. Calculates percentage change between anomalous period and average logins. Determines success and failure rate for logins for 1 hour period.'
description_detailed: |
  'This query over SiginLogs will summarise the total number of login attempts for each hour of the day on week days, this can be edited.
  The query then uses Kusto anomaly detection to find login spikes for each hour across all days. The query will then calculate the
  percentage change between the anomalous period and the average logins for that period. Finally the query will determine the success
  and failure rate for logins for the given 1 hour period, if a specified % change in logins is detected alongside a specified failure rate
  a result is presented.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto

  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = starttime - 14d;
  let failureThreshold = 15;
  let percentageChangeThreshold = 50;
  SigninLogs
  //Collect number of users logging in for each hour
  | where TimeGenerated >= lookback
  | summarize dcount(UserPrincipalName) by bin(TimeGenerated, 1h)
  | extend hour = datetime_part("Hour",TimeGenerated)
  | extend day = dayofweek(TimeGenerated)
  //Exclude Saturday and Sunday as they skew the data, change depending on your weekend days
  | where day != 6d and day != 7d
  | order by TimeGenerated asc
  //Summarise users trying to authenticate by each hour of the day
  | summarize make_list(dcount_UserPrincipalName), make_list(TimeGenerated), avg(dcount_UserPrincipalName), make_list(day) by hour
  //Find outlier hours where the number of users trying to authenticate spikes, expand and then keep only anomalous rows
  | extend series_decompose_anomalies(list_dcount_UserPrincipalName)
  | mv-expand list_dcount_UserPrincipalName, series_decompose_anomalies_list_dcount_UserPrincipalName_ad_flag, list_TimeGenerated, list_day
  | where series_decompose_anomalies_list_dcount_UserPrincipalName_ad_flag == 1
  //Calculate the percentage change between the spike and the average users authenticating
  | project TimeGenerated=todatetime(list_TimeGenerated), Hour=hour, WeekDay=list_day, AccountsAuthenticating=list_dcount_UserPrincipalName, AverageAccountsAuthenticatin=round(avg_dcount_UserPrincipalName, 0), PercentageChange = round  ((list_dcount_UserPrincipalName - avg_dcount_UserPrincipalName) / avg_dcount_UserPrincipalName * 100,   2)
  | order by PercentageChange desc
  //As an additional feature we collect successful and unsuccessful logins during the 1h windows with anomalies
  | join kind=inner(
  SigninLogs
  | where TimeGenerated >= lookback
  | where ResultType == "0"
  | summarize Success=dcount(UserPrincipalName), SuccessAccounts=make_set(UserPrincipalName) by bin(TimeGenerated, 1h)
  | join kind=inner(
      SigninLogs
      | where TimeGenerated >= lookback
      //Failed sign-ins based on failed username/password combos or failed MFA
      | where ResultType in ("50126", "50074", "50057", "51004")
      | summarize Failed=dcount(UserPrincipalName), FailedAccounts=make_set(UserPrincipalName) by bin(TimeGenerated, 1h)
  ) on TimeGenerated
  | project-away TimeGenerated1
  | extend Total = Failed + Success
  | project TimeGenerated, SuccessRate = round((toreal(Success) / toreal(Total)) *100) , round(FailureRate = (toreal(Failed) / toreal(Total)) *100), SuccessAccounts, FailedAccounts
  ) on TimeGenerated
  | order by PercentageChange
  | project-away TimeGenerated1
  //Thresholds, 15% account authentication failure rate at a 50% increase in accounts attempting to authenticate by default
  //Comment out line below to see all anomalous results
  | where FailureRate >= failureThreshold and PercentageChange >= percentageChangeThreshold
  | extend timestamp = TimeGenerated
  ```
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other", "Identity"]
---

