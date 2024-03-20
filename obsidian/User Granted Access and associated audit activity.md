---
id: 0da142a4-b3ad-4bb6-b01d-03b572743fe9
name: User Granted Access and associated audit activity
description: |
  'Identifies when a new user is granted access and any subsequent audit related activity.  This can help you identify rogue or malicious user behavior.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
  - PrivilegeEscalation
  - Impact
relevantTechniques:
  - T1098
  - T1078
  - T1496
query: "```kusto\n\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet auditLookback = starttime - 14d;\nlet opName = dynamic([\"Add user\", \"Invite external user\"]);\n// Setting threshold to 3 as a default, change as needed.  Any operation that has been initiated by a user or app more than 3 times in the past 14 days will be excluded\nlet threshold = 3;\n// Helper function to extract relevant fields from AuditLog events\nlet auditLogEvents = view (startTimeSpan:timespan)  {\n    AuditLogs | where TimeGenerated >= auditLookback\n    | extend ModProps = iff(TargetResources.[0].modifiedProperties != \"[]\", TargetResources.[0].modifiedProperties, todynamic(\"NoValues\"))\n    | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)), \n    tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))\n    | extend InitiatedByFull = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \n    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))\n    | extend InitiatedBy = replace(\"_\",\"@\",tostring(split(InitiatedByFull, \"#\")[0]))\n    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)\n    | extend TargetUserName = replace(\"_\",\"@\",tostring(split(TargetUserPrincipalName, \"#\")[0]))\n    | extend TargetResourceName = case(\n    isempty(tostring(TargetResources.[0].displayName)), TargetUserPrincipalName,\n    isnotempty(tostring(TargetResources.[0].displayName)) and tostring(TargetResources.[0].displayName) startswith \"upn:\", tolower(tostring(TargetResources.[0].displayName)),\n    tolower(tostring(TargetResources.[0].displayName))\n    )\n    | extend TargetUserName = replace(\"_\",\"@\",tostring(split(TargetUserPrincipalName, \"#\")[0]))\n    | extend TargetUserName = iff(isempty(TargetUserName), tostring(split(split(TargetResourceName, \",\")[0], \" \")[1]), TargetUserName ) \n    | mvexpand ModProps\n    | extend PropertyName = tostring(ModProps.displayName), newValue = replace('\\\"','',tostring(ModProps.newValue));\n};\nlet HistoricalAdd = auditLogEvents(auditLookback)\n| where OperationName in~ (opName)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), OperationCount = count() \nby Type, InitiatedBy, IpAddress, TargetUserName, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id\n// Remove comment below to only include operations initiated by a user or app that is above the threshold for the last 14 days\n| where OperationCount > threshold\n;\n// Get list of new added users to correlate with all other events\nlet Correlate = HistoricalAdd \n| summarize by InitiatedBy, TargetUserName, CorrelationId;\n// Get all other events related to list of newly added users\nlet allOtherEvents = auditLogEvents(auditLookback);\n// Join the new added user list to get the list of associated events\nlet CorrelatedEvents = Correlate \n| join allOtherEvents on InitiatedBy, TargetUserName\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) \nby Type, InitiatedBy, IpAddress, TargetUserName, TargetResourceName, Category, OperationName, PropertyName, newValue, CorrelationId, Id\n;\n// Union the results so we can see when the user was added and any associated events that occurred during the same time.\nlet Results = union isfuzzy=true HistoricalAdd,CorrelatedEvents;\n// newValues that are simple semi-colon separated, make those dynamic for easy viewing and Aggregate into the PropertyUpdate set based on CorrelationId and Id(DirectoryId)\nResults\n| extend newValue = split(newValue, \";\")\n| extend PropertyUpdate = pack(PropertyName, newValue, \"Id\", Id)\n| summarize StartTime = min(StartTimeUtc), EndTime = max(EndTimeUtc), PropertyUpdateSet = make_bag(PropertyUpdate) \nby InitiatedBy, IpAddress, TargetUserName, TargetResourceName, OperationName, CorrelationId\n| extend timestamp = StartTime, AccountCustomEntity = InitiatedBy, IPCustomEntity = IpAddress\n```"
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
    domains: ["Security - Other", "Identity"]
---

