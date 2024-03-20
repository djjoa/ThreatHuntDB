---
id: d82ea1db-f600-4c9e-8ba8-d271e9c12eb8
name: Lambda function throttled
description: |
  'Detected Lambda function throttled. Attacker could use this technique to result in Denial of Service. More about this API at https://docs.aws.amazon.com/lambda/latest/dg/API_PutFunctionConcurrency.html '
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Impact
relevantTechniques:
  - T1498
query: "```kusto\nAWSCloudTrail\n| where  EventName startswith \"PutFunctionConcurrency\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| where tostring(parse_json(RequestParameters).reservedConcurrentExecutions) == \"0\"\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData,UserIdentityArn, ResponseElements, FunctionName = tostring(parse_json(RequestParameters).functionName)\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = FunctionName\n```"
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

