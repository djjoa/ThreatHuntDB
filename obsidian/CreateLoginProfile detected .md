---
id: 4e3c81bf-61a4-47f4-b20d-a5a414ea08aa
name: CreateLoginProfile detected
description: |
  'An attacker could use CreateLoginProfile permissions on other users for privilege escalation by creating a password to a victim user without a login profile to use to login to the AWS Console.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: "```kusto\nAWSCloudTrail\n  | where  EventName == \"CreateLoginProfile\" and isempty(ErrorCode) and isempty(ErrorMessage)\n  | project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, UserIdentityArn, \n  UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements, RequestParameters\n  | extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n  | extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

