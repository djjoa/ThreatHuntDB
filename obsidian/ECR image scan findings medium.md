---
id: 4fbbae0a-ce5b-4b2a-b5e6-700920561680
name: ECR image scan findings medium
description: |
  'AWS ECR image scan detected medium severity vulnerabilities in your container image.'
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Execution
relevantTechniques:
  - T1204
query: "```kusto\nAWSCloudTrail\n| where EventName == \"DescribeImageScanFindings\" and isempty(ErrorCode) and isempty(ErrorMessage)\n| extend repoName = tostring(parse_json(ResponseElements).repositoryName)\n| extend imageId = tostring(parse_json(ResponseElements).imageId.imageDigest)\n| extend Medium = toint(parse_json(ResponseElements).imageScanFindings.findingSeverityCounts.MEDIUM)\n| where Medium > 0\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName \n```"
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

