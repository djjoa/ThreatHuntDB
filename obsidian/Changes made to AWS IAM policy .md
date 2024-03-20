---
id: e0a67cd7-b4e5-4468-aae0-26cb16a1bbd2
name: Changes made to AWS IAM policy
description: "'This query looks for when an API call is made to change an IAM, particularly those related to new policies being \nattached to users and roles, as well as changes to access methods and changes to account level policies.'  \n"
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
  - connectorId: AWSS3
    dataTypes:
      - AWSCloudTrail
tactics:
  - PrivilegeEscalation
  - DefenseEvasion
relevantTechniques:
  - T1078
  - T1484
query: "```kusto\n\nAWSCloudTrail\n| where  EventName in~ (\"AttachGroupPolicy\", \"AttachRolePolicy\", \"AttachUserPolicy\", \"CreatePolicy\",\n\"DeleteGroupPolicy\", \"DeletePolicy\", \"DeleteRolePolicy\", \"DeleteUserPolicy\", \"DetachGroupPolicy\",\n\"PutUserPolicy\", \"PutGroupPolicy\", \"CreatePolicyVersion\", \"DeletePolicyVersion\", \"DetachRolePolicy\", \"CreatePolicy\")\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nUserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityAccountId\n```"
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

