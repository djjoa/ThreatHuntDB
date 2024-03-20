---
id: f9f8b17c-52ed-4fd1-8edd-6278b6e2669f
name: Risky Sign-in with Device Registration
description: |
  'Looks for new device registrations following a risky user account sign-in. By default the
  query will use a 6 hour lookback period, this can be configured within the query.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
      - SigninLogs
tactics:
  - Persistence
relevantTechniques:
  - T1078.004
query: "```kusto\nlet timeDelta = 6h;\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet registeredDevices=AuditLogs\n| where TimeGenerated between (starttime .. endtime)\n| where OperationName =~ \"Add registered owner to device\" \n| where Identity =~ \"Device Registration Service\" \n| extend AccountUpn = tostring(TargetResources[0].userPrincipalName)\n| extend AccountObjectId = tostring(TargetResources[0].id)\n| extend DeviceObjectId = trim('\"', tostring(TargetResources[0].modifiedProperties[0].newValue))\n| extend DeviceDisplayName = trim('\"', tostring(TargetResources[0].modifiedProperties[1].newValue))\n| project DeviceRegistrationTimestamp=TimeGenerated,CorrelationId,AccountUpn,AccountObjectId,DeviceObjectId,DeviceDisplayName;\nlet registeringUser= \nregisteredDevices \n| distinct AccountObjectId;\nlet hasRegisteringUser = isnotempty(toscalar(registeringUser));\nlet riskySignins=SigninLogs\n| where TimeGenerated between ((starttime-timeDelta) .. endtime)\n| where hasRegisteringUser\n| where UserId in (registeringUser) \n| where RiskLevelDuringSignIn has_any ('medium', 'high')\n| where AppDisplayName in~ (\"Office 365 Exchange Online\", \"OfficeHome\") \n| where isnotempty(Id) \n| project SignInTimestamp=TimeGenerated, AppDisplayName, CorrelationId, AccountObjectId=UserId, IPAddress, RiskLevelDuringSignIn \n| summarize SignInTimestamp=argmin(SignInTimestamp,*) by AppDisplayName, CorrelationId, AccountObjectId, IPAddress, RiskLevelDuringSignIn;\nregisteredDevices \n| join riskySignins on AccountObjectId \n| where DeviceRegistrationTimestamp - SignInTimestamp < timeDelta //Time delta between risky sign-in and device registration less than 6h \n| project-away AccountObjectId1\n| extend timestamp = DeviceRegistrationTimestamp, AccountCustomEntity = AccountUpn, IPCustomEntity = IPAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountUpn
      - identifier: AadUserId
        columnName: AccountObjectId
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
version: 1.0.0
---

