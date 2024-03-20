---
id: 356aa5a8-fa6f-4eb9-baa9-ffcf725e3e82
name: S3 bucket has been deleted
description: |
  'Detected deletion of a S3 bucket. An attacker could delete S3 objects for impact and Denail of service purposes.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Impact
relevantTechniques:
  - T1485
query: "```kusto\nAWSCloudTrail\n| where  EventName == \"DeleteBucket\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, UserIdentityArn, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements, BucketName=tostring(parse_json(RequestParameters).bucketName)\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = BucketName\n```"
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

