---
id: 2b6a3882-d601-4298-983b-880f6dc7acdb
name: User Granted Access and Grants Access to Other Users
description: |
  'This query identifies when a new user is granted access and starts granting access to other users.  This can help you identify rogue or malicious user behavior.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098
  - T1078
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet auditLookback = starttime - 14d;\nlet opName = dynamic([\"Add user\", \"Invite external user\"]);\n// Helper function to extract relevant fields from AuditLog events\nlet auditLogEvents = view (startTimeSpan:timespan, operation:dynamic)  {\n    AuditLogs | where TimeGenerated >= auditLookback\n    | where OperationName in~ (operation)\n    | extend ModProps = iff(TargetResources.[0].modifiedProperties != \"[]\", TargetResources.[0].modifiedProperties, todynamic(\"NoValues\"))\n    | extend IpAddress = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)), \n    tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), tostring(parse_json(tostring(InitiatedBy.app)).ipAddress))\n    | extend InitiatedByFull = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), \n    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))\n    | extend InitiatedBy = replace(\"_\",\"@\",tostring(split(InitiatedByFull, \"#\")[0]))\n    | extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName)\n    | extend TargetUserName = replace(\"_\",\"@\",tostring(split(TargetUserPrincipalName, \"#\")[0]))\n    | extend TargetResourceName = case(\n    isempty(tostring(TargetResources.[0].displayName)), TargetUserPrincipalName,\n    isnotempty(tostring(TargetResources.[0].displayName)) and tostring(TargetResources.[0].displayName) startswith \"upn:\", tolower(tostring(TargetResources.[0].displayName)),\n    tolower(tostring(TargetResources.[0].displayName))\n    )\n    | extend TargetUserName = replace(\"_\",\"@\",tostring(split(TargetUserPrincipalName, \"#\")[0]))\n    | extend TargetUserName = iff(isempty(TargetUserName), tostring(split(split(TargetResourceName, \",\")[0], \" \")[1]), TargetUserName ) \n    | mvexpand ModProps\n    | extend PropertyName = tostring(ModProps.displayName), newValue = replace('\\\"','',tostring(ModProps.newValue));\n};\n// Assigning time for First TargetUserName that was added\nlet FirstAdd = auditLogEvents(auditLookback, opName)  \n| project FirstAddTimeUtc = TimeGenerated, Type, FirstInitiatedBy = InitiatedBy, IpAddress, FirstTargetUserName = TargetUserName, FirstTargetResourceName = TargetResourceName, \nFirstOperationName = OperationName, FirstPropertyName = PropertyName, FirstnewValue = newValue, FirstCorrelationId = CorrelationId, FirstId = Id;\n// Assigning time for second TargetUserName that was added, which will allow us to see if a first TargetUserName added in is the Initiated by on the second in the later join\nlet SecondAdd = auditLogEvents(auditLookback, opName)  \n| project SecondAddTimeUtc = TimeGenerated, Type, SecondInitiatedBy = InitiatedBy, IpAddress, SecondTargetUserName = TargetUserName, SecondTargetResourceName = TargetResourceName, \nSecondOperationName = OperationName, SecondPropertyName = PropertyName, SecondnewValue = newValue, SecondCorrelationId = CorrelationId, SecondId = Id;\n//  Joining the FirstAdd with SecondAdd where the FirstAdd TargetUserName value matches the SecondAdd InitiatedBy.  This shows the new user adding a user.\nlet NewUserAddsUser = FirstAdd | join SecondAdd on $left.FirstTargetUserName == $right.SecondInitiatedBy\n// we only want items where the FirstAddTimeUtc is before the SecondAddTimeUtc\n| where FirstAddTimeUtc < SecondAddTimeUtc\n;\n// Build out some of the properties for context\nNewUserAddsUser\n| extend FirstnewValue = split(FirstnewValue, \";\"), SecondnewValue = split(SecondnewValue, \";\")\n| extend PropertyUpdate = pack(FirstPropertyName, FirstnewValue, SecondPropertyName, SecondnewValue, \"FirstCorrelationId\", FirstCorrelationId, \"FirstId\", FirstId, \"SecondCorrelationId\", SecondCorrelationId, \"SecondId\", SecondId)\n| summarize PropertyUpdateSet = make_bag(PropertyUpdate, 1000) by FirstAddTimeUtc, FirstInitiatedBy, FirstTargetUserName, SecondAddTimeUtc, SecondInitiatedBy, SecondTargetUserName, \nIpAddress, FirstTargetResourceName, SecondTargetResourceName, FirstOperationName, SecondOperationName\n| extend timestamp = FirstAddTimeUtc, FirstInitiatedByUserName = tostring(strcat_array(array_slice(split(FirstInitiatedBy, '@'), 0, -2), '@')), FirstInitiatedByUPNSuffix = tostring(split(FirstInitiatedBy, '@')[-1])\n| extend Account_0_Name = FirstInitiatedByUserName\n| extend Account_0_UPNSuffix = FirstInitiatedByUPNSuffix\n| extend IP_0_Address = IpAddress\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: FirstInitiatedByUserName
      - identifier: UPNSuffix
        columnName: FirstInitiatedByUPNSuffix
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
version: 1.0.2
---

