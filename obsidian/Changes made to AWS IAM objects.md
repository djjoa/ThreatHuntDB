---
id: d022a62c-643b-4e8a-b583-0230e32a96e4
name: Changes made to AWS IAM objects
description: "'Identity and Access Management (IAM) securely manages access to AWS services and resources.\nThis query looks for when an API call is made to change an IAM, particularly those related to new objects being created or deleted. If these turn out to be noisy, filter out the most common for your environment.'  \n"
severity: Medium
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - PrivilegeEscalation
  - DefenseEvasion
relevantTechniques:
  - T1078
  - T1484
query: "```kusto\nAWSCloudTrail\n | where  EventName in~ (\"DeleteUser\", \"DeleteGroup\", \"CreateUser\") and isempty(ErrorMessage) and isempty(ErrorCode)\n | project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \n   UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements\n | extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityAccountId\n```"
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

