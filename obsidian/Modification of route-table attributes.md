---
id: 3b7df29e-a798-4b6b-9ef7-73b9a3cf56a2
name: Modification of route-table attributes
description: |
  'An attacker could modify route-table attributes in order to access resources he couldn't access before.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Defense Evasion
relevantTechniques:
  - T1562
query: "```kusto\nAWSCloudTrail\n| where  EventName in (\"CreateRoute\",\"DeleteRoute\",\"ReplaceRoute\") and isempty(ErrorCode) and isempty(ErrorMessage)\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, SessionMfaAuthenticated,UserIdentityArn, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

