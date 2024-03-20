---
id: 53b6d42e-ff74-46a8-abee-ec72181f66ba
name: Sign-ins from IPs that attempt sign-ins to disabled accounts
description: |
  'Identifies IPs with failed attempts to sign in to one or more disabled accounts signed in successfully to another account.
  This analytic will additionally identify the successful signed in accounts as the mapped account entities for investigation.
  References: https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
  50057 - User account is disabled. The account has been disabled by an administrator.'
severity: Medium
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: 1d
queryPeriod: 1d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - InitialAccess
  - Persistence
relevantTechniques:
  - T1078
  - T1098
query: "```kusto\nlet threshold = 100;\nSigninLogs \n| where ResultType == \"50057\" \n| where ResultDescription == \"User account is disabled. The account has been disabled by an administrator.\" \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), disabledAccountLoginAttempts = count(), \ndisabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted = dcount(AppDisplayName), disabledAccountSet = makeset(UserPrincipalName), \napplicationSet = makeset(AppDisplayName) by IPAddress\n| order by disabledAccountLoginAttempts desc\n| join kind= leftouter (\n    // Consider these IPs suspicious - and alert any related  successful sign-ins\n    SigninLogs\n    | where ResultType == 0\n    | summarize successSigninStart = min(TimeGenerated), successSigninEnd = max(TimeGenerated), successfulAccountSigninCount = dcount(UserPrincipalName), successfulAccountSigninSet = makeset(UserPrincipalName, 15) by IPAddress\n    // Assume IPs associated with sign-ins from 100+ distinct user accounts are safe\n    | where successfulAccountSigninCount < threshold\n) on IPAddress  \n// IPs from which attempts to authenticate as disabled user accounts originated, and had a non-zero success rate for some other account\n| where successfulAccountSigninCount != 0\n// Successful Account Signins occur within the same lookback period as the failed \n| extend SuccessBeforeFailure = iff(successSigninStart >= StartTime and successSigninEnd <= EndTime, true, false)  \n| project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts, disabledAccountsTargeted, disabledAccountSet, applicationSet, \nsuccessfulAccountSigninCount, successfulAccountSigninSet\n| order by disabledAccountLoginAttempts\n// Break up the string of Succesfully signed into accounts into individual events\n| mvexpand successfulAccountSigninSet\n| extend timestamp = StartTime, IPCustomEntity = IPAddress\n```"
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

