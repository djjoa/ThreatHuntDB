---
id: 838f59d4-fe47-422b-819d-1be502940547
name: Login profile updated
description: |
  'An attacker could use UpdateLoginProfile permissions for privilege escalation by changing the victim user password. More about this API at https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateLoginProfile.html '
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: "```kusto\nAWSCloudTrail\n| where  EventName == \"UpdateLoginProfile\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource,UserIdentityArn, AdditionalEventData, ResponseElements, RequestParameters\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

