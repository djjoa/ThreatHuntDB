---
id: 66fb97d1-55c3-4268-ac22-b9742d0fdccc
name: Rare domains seen in Cloud Logs
description: |
  'This script identifies rare domain accounts accessing cloud resources by examining logs. You can lower the domainLimit value to see domains with fewer access attempts. For example, set domainLimit = 2 to see domains with 2 or fewer access attempts.'
description_detailed: "'This will identify rare domain accounts accessing or attempting to access cloud resources by examining the AuditLogs, OfficeActivity and SigninLogs\nRare does not mean malicious, but it may be something you would be interested in investigating further\nAdditionally, it is possible that there may be many domains if you have allowed access by 3rd party domain accounts.\nLower the domainLimit value as needed.  For example, if you only want to see domains that have an access attempt count of 2 or less,\nthen set domainLimit = 2 below.  If you need to set it lower only for a given log, then use customLimit in the same way and uncomment \nthat line in the script.'\n"
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
      - AuditLogs
  - connectorId: Office365
    dataTypes:
      - OfficeActivity
tactics:
  - InitialAccess
  - Discovery
  - Collection
relevantTechniques:
  - T1190
  - T1087
  - T1114
query: "```kusto\n\n// Provide customLimit value with default above domainLimit value so it will not block unless changed\nlet customLimit = 11;\nlet domainLimit = 10;\nlet domainLookback = union isfuzzy=true\n(AuditLogs\n| extend UserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))\n// parse out AuditLog values for various locations where UPN could be\n| extend UserPrincipalName = iff(isnotempty(UserPrincipalName),\nUserPrincipalName, \niif((tostring(InitiatedBy.user.userPrincipalName)=='unknown'), \nextract(\"Email: ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\\\.[a-zA-Z0-9-.]+)\", 1, tostring(parse_json(TargetResources)[0].displayName)), \nInitiatedBy.user.userPrincipalName))\n| where UserPrincipalName has \"@\" or UserPrincipalName startswith \"NT AUTHORITY\"\n| extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n| where isnotempty(RareDomain) \n| summarize RareDomainCount = count() by Type, RareDomain,UserPrincipalName\n| where RareDomainCount <= domainLimit\n| extend AccountCustomEntity = UserPrincipalName\n// remove comment from below if you would like to have a lower limit for RareDomainCount specific to AuditLog\n//| where RareDomainCount <= customLimit\n),\n(OfficeActivity\n| extend UserPrincipalName = tolower(UserId)\n| where UserPrincipalName has \"@\" or UserPrincipalName startswith \"NT AUTHORITY\"\n| extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n| summarize RareDomainCount = count() by Type, RareDomain, UserPrincipalName\n| where RareDomainCount <= domainLimit\n| extend AccountCustomEntity = UserPrincipalName\n// remove comment from below if you would like to have a lower limit for RareDomainCount specific to OfficeActivity\n//| where RareDomainCount <= customLimit\n),\n(SigninLogs\n| where UserPrincipalName has \"@\" or UserPrincipalName startswith \"NT AUTHORITY\"\n| extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n| summarize RareDomainCount = count() by Type, RareDomain\n| where RareDomainCount <= domainLimit\n// remove comment from below if you would like to have a lower limit for RareDomainCount specific to SigninLogs\n//| where RareDomainCount <= customLimit\n);\nlet AuditLogsRef = domainLookback | join (\n   AuditLogs\n   | extend UserPrincipalName = tolower(tostring(TargetResources.[0].userPrincipalName))\n   | extend UserPrincipalName = iff(isempty(UserPrincipalName), tostring(InitiatedBy.user.userPrincipalName), UserPrincipalName)\n   | extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n   | where isnotempty(RareDomain) \n   | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category, Result\n   | extend AccountCustomEntity = UserPrincipalName\n) on Type, RareDomain;\nlet OfficeActivityRef = domainLookback | join (\n    OfficeActivity\n    | extend UserPrincipalName = tolower(UserId)\n    | where UserPrincipalName has \"@\" or UserPrincipalName startswith \"NT AUTHORITY\"\n    | extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n    | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName = Operation, Category = OfficeWorkload, Result = ResultStatus\n    | extend AccountCustomEntity = UserPrincipalName\n) on Type, RareDomain;\nlet SigninLogsRef = domainLookback | join (\n    SigninLogs\n    | extend UserPrincipalName = tolower(UserId)\n    | where UserPrincipalName has \"@\" or UserPrincipalName startswith \"NT AUTHORITY\"\n    | extend RareDomain = toupper(tostring(split(UserPrincipalName, \"@\")[-1]))\n    | summarize UPNRefCount = count() by TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category = AppDisplayName, Result = ResultType\n    | extend AccountCustomEntity = UserPrincipalName\n) on Type, RareDomain;\nlet Results = union isfuzzy=true\nAuditLogsRef,OfficeActivityRef,SigninLogsRef;\nResults | project TimeGenerated, Type, RareDomain, UserPrincipalName, OperationName, Category, Result, UPNRefCount \n| order by TimeGenerated asc \n| extend timestamp = TimeGenerated, AccountCustomEntity = UserPrincipalName\n```"
version: 1.0.2
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

