---
id: 05167149-4670-4a9f-b34e-5a0a92243194
name: Modification of subnet attributes
description: |
  'An attacker could modify subnet attributes in order to access resources he couldn't access before.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Defense Evasion
relevantTechniques:
  - T1562
query: "```kusto\nAWSCloudTrail\n| where  EventName == \"ModifySubnetAttribute\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, UserIdentityArn, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

