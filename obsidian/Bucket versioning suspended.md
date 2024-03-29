---
id: 48c49b1d-2aa0-442b-96e3-cae6ad1251cd
name: Bucket versioning suspended
description: |
  'Detected Bucket versioning suspended event. Attackers could use this technique to be able to ransom buckets without the option for the victim to have a backup.'
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Impact
relevantTechniques:
  - T1485
query: |-
  ```kusto
  AWSCloudTrail
  | where EventName == "PutBucketVersioning" and isempty(ErrorCode) and isempty(ErrorMessage)
  | extend status = tostring(parse_json(RequestParameters).VersioningConfiguration.Status)
  | where status == "Suspended"
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

