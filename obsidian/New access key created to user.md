---
id: a2772445-9bb1-4176-9481-b262cb59118a
name: New access key created to user
description: |
  'An attacker with the CreateAccessKey permissions on other users can create an access Key ID and secret access key belonging to another user in the AWS environment for privilege escalation.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: "```kusto\nAWSCloudTrail\n| where  EventName == \"CreateAccessKey\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData,UserIdentityArn, ResponseElements, RequestParameters\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

