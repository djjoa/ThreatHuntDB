---
id: e1a91db8-f2b3-4531-bff6-da133d4f4f1a
name: IAM Privilege Escalation by Instance Profile attachment
description: "'An instance profile is a container for an IAM role that you can use to pass role information to an EC2 instance when the instance start.\nIdentifies when existing role is removed and new/existing high privileged role is added to instance profile. \nAny instance with this instance profile attached is able to perform privileged operations.\nAWS Instance Profile: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html\nand CloudGoat - IAM PrivilegeEscalation by Attachment: https://github.com/RhinoSecurityLabs/cloudgoat/tree/master/scenarios/iam_privesc_by_attachment'\n"
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
  - connectorId: AWSS3
    dataTypes:
      - AWSCloudTrail
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1098
query: "```kusto\n\n// Creating separate table for RemoveRoleToInstanceProfile\nlet RemoveRole=AWSCloudTrail\n| where  EventName in~ (\"RemoveRoleFromInstanceProfile\") and isempty(ErrorMessage)\n| extend RoleRemoved = tostring(parse_json(RequestParameters).roleName), InstanceProfileName = tostring(parse_json(RequestParameters).instanceProfileName), TimeRemoved=TimeGenerated\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| summarize RoleRemovedCount= dcount(TimeRemoved) by TimeRemoved, EventName, EventTypeName, UserIdentityArn, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nSourceIpAddress, AWSRegion, EventSource, RoleRemoved, InstanceProfileName;\n// Creating separate table for AddRoleToInstanceProfile\nlet AddRole=AWSCloudTrail\n| where  EventName in~ (\"AddRoleToInstanceProfile\") and isempty(ErrorMessage)\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend RoleAdded = tostring(parse_json(RequestParameters).roleName), InstanceProfileName = tostring(parse_json(RequestParameters).instanceProfileName), TimeAdded=TimeGenerated\n| summarize RoleAddedCount= dcount(TimeAdded) by TimeAdded, EventName, EventTypeName, UserIdentityArn, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, \nSourceIpAddress, AWSRegion, EventSource, RoleAdded, InstanceProfileName;\n//Joining both operations from the same source IP, user and instance profile name\nRemoveRole\n| join kind= inner (\n   AddRole \n) on AWSRegion,SourceIpAddress, InstanceProfileName, UserIdentityUserName\n| where TimeAdded  > TimeRemoved // Checking if RoleAdd operation was performed after removal\n| summarize TotalCount=count() by TimeAdded, TimeRemoved, RoleAdded, RoleRemoved, UserIdentityUserName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent,\nSourceIpAddress, AWSRegion, EventSource, RoleRemovedCount, RoleAddedCount\n| extend timestamp = iff(TimeAdded > TimeRemoved,TimeAdded, TimeRemoved), IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName\n```"
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

