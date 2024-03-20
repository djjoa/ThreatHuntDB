---
id: 3d217bb4-9cc2-4aba-838a-48e606e910e6
name: Low & slow password attempts with volatile IP addresses
description: "'This hunting query will identify instances where a single user account has seen a high incidence of failed attempts from highly volatile IP addresses\n Changing IP address for every password attempt is becoming a more common technique amongst sophisticated threat groups. Often threat groups will randomise \n the user agent they are using as well as IP address. This technique has been enabled by the emergence of services providing huge numbers of residential IP \n addresses. These services are often enabled through malicious browser plugins. This query is best executed over longer timeframes.\n Reduce the timeRange if you have too much data. Results with the highest \"IPs\", \"Failures\" and \"DaysWithAttempts\" are good candidates for further\n investigation. This query intentionally does not cluster on UserAgent, IP etc. This query is clustering on the highly volatile IP behaviour.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
  - CredentialAccess
relevantTechniques:
  - T1078
  - T1078.004
  - T1110
  - T1110.004
  - T1110.003
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet timeRange = 365d;\nlet UnsuccessfulLoginCountryThreshold = 5; // Number of failed countries attempting to login, good way to filter.\nSigninLogs\n| where TimeGenerated between(starttime..endtime)\n// Limit to username/password failure errors, most common when bruteforcing/spraying\n| where ResultType has_any(\"50055\",\"50126\")\n// Find instances where an IP has only been used once\n| summarize IPLogins=count(), make_list(TimeGenerated) by IPAddress, Location, UserPrincipalName \n| where IPLogins == 1\n// We only keep instances where there is 1 event, so we know there will only be one datetime in the list\n| extend LoginAttemptTime = format_datetime(todatetime(list_TimeGenerated[0]), 'dd-MM-yyyy')\n// So far we've only collected failures, we join back to the log to ensure there were no successful logins from the IP\n| join kind=leftouter (\n    SigninLogs\n    | where TimeGenerated > ago(timeRange)\n    | where ResultType == 0\n    | summarize count() by IPAddress, UserPrincipalNameSuccess=UserPrincipalName\n) on $left.IPAddress == $right.IPAddress\n// Where there have been fewer than 2 successful logins from the IP\n| where count_ < 2 or isempty(count_)\n// Confirm that the result is for the same account where possible\n| where UserPrincipalName == UserPrincipalNameSuccess or isempty(UserPrincipalNameSuccess)\n// Summarize the collected details around the users email address\n| mv-expand list_TimeGenerated to typeof(datetime)\n| summarize IPs=dcount(IPAddress), UnsuccessfulLoginCountryCount=dcount(Location), make_list(IPAddress), make_list(Location), DaysWithAttempts=dcount(LoginAttemptTime), Failures=count(), StartTime=min(list_TimeGenerated), EndTime=max(list_TimeGenerated) by UserPrincipalName\n| project UserPrincipalName, StartTime, EndTime, Failures, IPs, UnsuccessfulLoginCountryCount, DaysWithAttempts, IPAddresses=list_IPAddress, IPAddressLocations=list_Location\n// Join back to get countries the user has successfully authenticated from to compare with failures\n| join kind=leftouter (\n    SigninLogs\n    | where TimeGenerated > ago(timeRange)\n    | where ResultType == 0\n    // If there is no location make the output pretty\n    | extend Location = iff(isempty(Location), \"NODATA\", Location)\n    | summarize SuccessfulLoginCountries=make_set(Location), SuccessfulLoginCountryCount=dcount(Location) by UserPrincipalName\n) on $left.UserPrincipalName == $right.UserPrincipalName\n| project-away UserPrincipalName1\n| order by UnsuccessfulLoginCountryCount desc\n// Calculate the difference between countries with successful vs. failed logins\n| extend IPIncreaseOnSuccess = UnsuccessfulLoginCountryCount - SuccessfulLoginCountryCount\n// The below line can be removed if the actor is using IPs in one country\n| where UnsuccessfulLoginCountryCount > UnsuccessfulLoginCountryThreshold\n| project StartTime, EndTime, UserPrincipalName, Failures, IPs, DaysWithAttempts, UnsuccessfulLoginCountryCount, UnuccessfulLoginCountries=IPAddressLocations, SuccessfulLoginCountries, FailureIPAddresses=IPAddresses\n| extend timestamp = StartTime, AccountCustomEntity = UserPrincipalName, IPCustomEntity = FailureIPAddresses\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: UserPrincipalName
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddresses
version: 1.0.0
---

