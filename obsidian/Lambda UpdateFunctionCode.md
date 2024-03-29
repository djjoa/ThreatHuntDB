---
id: 2dd2143b-6667-4a7a-b04f-98d22caeffac
name: Lambda UpdateFunctionCode
description: |
  'This analytic is designed to detect an IAM user updating AWS lambda code via AWS CLI to gain persistent, further access into your AWS environment and to facilitate panting backdoors. An attacker may upload malicious code/binary to a lambda function which will be executed automatically when the function is triggered.'
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Execution
relevantTechniques:
  - T1204
query: |-
  ```kusto
  AWSCloudTrail
  | where EventName startswith 'UpdateFunctionCode' and EventSource == "lambda.amazonaws.com" and UserIdentityType =='IAMUser' and isempty(ErrorCode) and isempty(ErrorMessage)
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

