---
id: 6eb59239-78c5-401d-acfa-5cb9b3d31cd4
name: S3 bucket encryption modified
description: |
  'Detected modification of bucket encryption. An attacker could modify encryption of existing buckets for denial of service attacks.'
severity: Low
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Impact
relevantTechniques:
  - T1486
query: |-
  ```kusto
  AWSCloudTrail
  | where EventName in ("PutBucketEncryption","DeleteBucketEncryption") and isempty(ErrorCode) and isempty(ErrorMessage)
  | extend encryptionConfig = tostring(parse_json(RequestParameters).ServerSideEncryptionConfiguration.Rule)
  | where encryptionConfig contains RecipientAccountId
  | extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))
  | extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName
  ```
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

