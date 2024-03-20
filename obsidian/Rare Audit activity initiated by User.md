---
id: ea107ccc-2b80-410e-96e1-be6607ce293b
name: Rare Audit activity initiated by User
description: |
  'Compares current day to last 14 days of audits to identify new audit activities. Useful for tracking malicious activity related to user/group additions/removals by specific users.'
description_detailed: "'Compares the current day to the last 14 days of audits to identify new audit activities by \nOperationName, InitiatedByUser, UserPrincipalName, PropertyName, newValue\nThis can be useful when attempting to track down malicious activity related to additions of \nnew users, additions to groups, removal from groups by specific users.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
  - LateralMovement
relevantTechniques:
  - T1136
query: "```kusto\n\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet auditLookback = starttime - 14d;\nlet propertyIgnoreList = dynamic([\"TargetId.UserType\", \"StsRefreshTokensValidFrom\", \"LastDirSyncTime\", \"DeviceOSVersion\", \"CloudDeviceOSVersion\", \"DeviceObjectVersion\"]);\nlet AuditTrail = AuditLogs \n| where TimeGenerated >= auditLookback and TimeGenerated < starttime\n| where isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))\n| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)\n| extend InitiatedByIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n| extend ModProps = TargetResources.[0].modifiedProperties\n| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))\n| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))\n| mv-expand ModProps\n| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])\n| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ \"Action Client Name\" and newValue !~ \"DirectorySync\") and (PropertyName !~ \"Included Updated Properties\" and newValue !~ \"LastDirSyncTime\")\n| summarize count() by OperationName, InitiatedByUser, InitiatedByIPAddress, TargetUserPrincipalName, PropertyName, TargetResourceName;\nlet AccountMods = AuditLogs \n| where TimeGenerated >= starttime\n| where isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName))\n| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)\n| extend InitiatedByIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)\n| extend ModProps = TargetResources.[0].modifiedProperties\n| extend TargetUserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))\n| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))\n| mv-expand ModProps\n| extend PropertyName = tostring(ModProps.displayName), newValue = tostring(parse_json(tostring(ModProps.newValue))[0])\n| where PropertyName !in~ (propertyIgnoreList) and (PropertyName !~ \"Action Client Name\" and newValue !~ \"DirectorySync\") and (PropertyName !~ \"Included Updated Properties\" and newValue !~ \"LastDirSyncTime\")\n| extend ModifiedProps = pack(\"PropertyName\",PropertyName,\"newValue\",newValue, \"Id\", Id, \"CorrelationId\", CorrelationId) \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), Activity = make_bag(ModifiedProps) by Type, InitiatedByUser, InitiatedByIPAddress, TargetUserPrincipalName, Category, OperationName, PropertyName, TargetResourceName;\nlet RareAudits = AccountMods | join kind= leftanti (\n   AuditTrail \n) on OperationName, InitiatedByUser, InitiatedByIPAddress;//, TargetUserPrincipalName, PropertyName; //uncomment if you want to see Rare Property changes to a given TargetUserPrincipalName.\nRareAudits \n| summarize StartTime = min(StartTimeUtc), EndTime = max(EndTimeUtc), make_set(Activity), make_set(PropertyName) by Type, InitiatedByUser, InitiatedByIPAddress, OperationName, TargetUserPrincipalName, TargetResourceName\n| order by InitiatedByUser asc, StartTime asc\n| extend timestamp = StartTime, AccountCustomEntity = InitiatedByUser, HostCustomEntity = iff(set_PropertyName has_any ('DeviceOSType', 'CloudDeviceOSType'), TargetResourceName, ''), IPCustomEntity = InitiatedByIPAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
version: 1.0.1
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

