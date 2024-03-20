---
id: bac44fe4-c0bc-4e90-aa48-2e346fda803f
name: Tracking Password Changes
description: |
  'This script identifies password changes or resets across multiple host and cloud sources. Account manipulation, including password changes and resets, may help adversaries maintain access to credentials and permission levels.'
description_detailed: "'Identifies when a password change or reset occurs across multiple host and cloud based sources. \nAccount manipulation including password changes and resets may aid adversaries in maintaining access to credentials \nand certain permission levels within an environment.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: Syslog
    dataTypes:
      - Syslog
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvents
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - InitialAccess
  - CredentialAccess
relevantTechniques:
  - T1078
  - T1110
query: "```kusto\n\nlet action = dynamic([\"change \", \"changed \", \"reset \"]);\nlet pWord = dynamic([\"password \", \"credentials \"]);\n(union isfuzzy=true\n  (SecurityEvent\n| where EventID in (4723,4724)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(Activity), ActionCount = count() by Resource = Computer, OperationName = strcat(\"TargetAccount: \", TargetUserName), UserId = Account, Type\n),\n(WindowsEvent\n| where EventID in (4723,4724)\n| extend Activity=iff(EventID=='4723',\"4723 - An attempt was made to change an account\",\"4724 - An attempt was made to reset an account\")\n| extend TargetUserName = tostring(EventData.TargetUserName)\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(Activity), ActionCount = count() by Resource = Computer, OperationName = strcat(\"TargetAccount: \", TargetUserName), UserId = Account, Type\n),\n(AuditLogs\n| where OperationName has_any (pWord) and OperationName has_any (action)\n| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) \n| extend TargetUserPrincipalName = tostring(TargetResources[0].userPrincipalName) \n| where ResultDescription != \"None\" \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescription), CorrelationIds = makeset(CorrelationId), ActionCount = count() by OperationName = strcat(Category, \" - \", OperationName, \" - \", Result), Resource, UserId = TargetUserPrincipalName, Type\n| extend ResultDescriptions = tostring(ResultDescriptions)\n),\n(OfficeActivity\n| where (ExtendedProperties has_any (pWord) or ModifiedProperties has_any (pWord)) and (ExtendedProperties has_any (action) or ModifiedProperties has_any (action))\n| extend ResultDescriptions = case(\nOfficeWorkload =~ \"AzureActiveDirectory\", tostring(ExtendedProperties),\nOfficeWorkload has_any (\"Exchange\",\"OneDrive\"), OfficeObjectId,\nRecordType) \n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescriptions), ActionCount = count() by Resource = OfficeWorkload, OperationName = strcat(Operation, \" - \", ResultStatus), IPAddress = ClientIP, UserId, Type\n),\n(Syslog\n| where SyslogMessage has_any (pWord) and SyslogMessage has_any (action)\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(SyslogMessage), ActionCount = count() by Resource = HostName, OperationName = Facility , IPAddress = HostIP, ProcessName, Type\n),\n(SigninLogs\n| where OperationName =~ \"Sign-in activity\" and ResultType has_any (\"50125\", \"50133\")\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ResultDescriptions = makeset(ResultDescription), CorrelationIds = makeset(CorrelationId), ActionCount = count() by Resource, OperationName = strcat(OperationName, \" - \", ResultType), IPAddress, UserId = UserPrincipalName, Type\n)\n)\n| extend timestamp = StartTimeUtc, AccountCustomEntity = UserId, IPCustomEntity = IPAddress\n```"
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

