---
id: b09d6e57-c48b-491d-9c2b-ab73018e6534
name: Consent to Application discovery
description: |
  'This query looks at the last 14 days for "Consent to application" operation by a user/app which could potentially mean unauthorized access. Additional context is added from AuditLogs based on CorrleationId from the same account that performed the action.'
description_detailed: |
  'This query looks at the last 14 days for any "Consent to application" operation
  occurs by a user or app. This could indicate that permissions to access the listed AzureApp
  was provided to a malicious actor. Consent to appliction, Add service principal and
  Add OAuth2PermissionGrant events should be rare. If available, additional context is added
  from the AuditLogs based on CorrleationId from the same account that performed "Consent to
  application".
  For further information on AuditLogs please see
  https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities
  This may help detect the Oauth2 attack that can be initiated by this publicly available tool
  https://github.com/fireeye/PwnAuth'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
relevantTechniques:
  - T1136
query: |-
  ```kusto

  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let auditLookback = starttime - 14d;
  // Setting threshold to 3 as a default, change as needed.  Any operation that has been initiated by a user or app more than 3 times in the past 30 days will be exluded
  let threshold = 3;
  // Helper function to extract relevant fields from AuditLog events
  let auditLogEvents = view (startTimeSpan:timespan)  {
      AuditLogs | where TimeGenerated >= auditLookback
      | extend ModProps = TargetResources.[0].modifiedProperties
      | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)),
      tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))
      | extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)),
      tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
      | extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
      | mvexpand ModProps
      | extend PropertyName = tostring(ModProps.displayName), newValue = replace('\"',"",tostring(ModProps.newValue));
  };
  // Get just the InitiatedBy and CorrleationId so we can look at associated audit activity
  // 2 other operations that can be part of malicious activity in this situation are
  // "Add OAuth2PermissionGrant" and "Add service principal", replace the below if you are interested in those as starting points for OperationName
  let HistoricalConsent = auditLogEvents(auditLookback)
  | where OperationName == "Consent to application"
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count()
  by Type, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id
  // Remove comment below to only include operations initiated by a user or app that is above the threshold for the last 30 days
  //| where OperationCount > threshold
  ;
  let Correlate = HistoricalConsent
  | summarize by InitiatedBy, CorrelationId;
  // 2 other operations that can be part of malicious activity in this situation are
  // "Add OAuth2PermissionGrant" and "Add service principal", replace the below if you changed the starting OperationName above
  let allOtherEvents = auditLogEvents(auditLookback)
  | where OperationName != "Consent to application";
  // Gather associated activity based on audit activity for "Consent to application" and InitiatedBy and CorrleationId
  let CorrelatedEvents = Correlate
  | join allOtherEvents on InitiatedBy, CorrelationId
  | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated)
  by Type, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id
  ;
  // Union the results
  let Results = (union isfuzzy=true HistoricalConsent,CorrelatedEvents);
  // newValues that are simple semi-colon separated, make those dynamic for easy viewing and Aggregate into the PropertyUpdate set based on CorrelationId and Id(DirectoryId)
  Results
  | extend newValue = split(newValue, ";")
  | extend PropertyUpdate = pack(PropertyName, newValue, "Id", Id)
  // Extract scope requested
  | extend perms = tostring(parse_json(tostring(PropertyUpdate.["ConsentAction.Permissions"]))[0])
  | extend scope = extract('Scope:\\s*([^,\\]]*)',1, perms)
  // Filter out some common openid, and low privilege request scopes - uncomment line below to filter out where no scope is requested
  //| where isnotempty(scope)
  | where scope !contains 'openid' and scope !in ('user_impersonation','User.Read')
  | summarize StartTime = min(StartTimeUtc), EndTime = max(EndTimeUtc), PropertyUpdateSet = make_bag(PropertyUpdate) , make_set(scope)
    by InitiatedBy, IpAddress, TargetResourceName, OperationName, CorrelationId
  | extend timestamp = StartTime, AccountCustomEntity = InitiatedBy, IPCustomEntity = IpAddress
  // uncommnet below to summarize by app if many results
  //| summarize make_set(InitiatedBy), make_set(IpAddress), make_set(PropertyUpdateSet) by TargetResourceName, tostring(set_scope)
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Shain
  support:
    tier: Community
  categories:
    domains: ["Security - Threat Protection"]
---

