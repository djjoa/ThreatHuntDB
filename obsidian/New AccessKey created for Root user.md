---
id: 4055466c-8a84-44c6-91d0-46469f3ba0b9
name: New AccessKey created for Root user
description: |
  'Attackers with the CreateAccessKey permissions for other users can create an access Key ID and secret access key belonging to another user in the AWS environment for privilege escalation.'
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Persistence
relevantTechniques:
  - T1078
query: "```kusto\nAWSCloudTrail\n  | where  EventName == \"CreateAccessKey\" and tostring(parse_json(RequestParameters).userName) == \"Root\" and isempty(ErrorCode) and isempty(ErrorMessage)\n  | project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \n  UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource,UserIdentityArn, AdditionalEventData, ResponseElements, RequestParameters\n  | extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n  | extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

