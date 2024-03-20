---
id: 0db42a94-e7c8-4bf1-99a7-1a2fb4158212
name: Privileged role attached to Instance
description: "'Identity and Access Management (IAM) securely manages access to AWS services and resources. \nIdentifies when a Privileged role is attached to an existing instance or new instance at deployment. This instance may be used by an adversary to escalate a normal user privileges to an adminsitrative level.\nand AWS API AddRoleToInstanceProfile at https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddRoleToInstanceProfile.html'\n"
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
query: "```kusto\n\nlet EventNameList = dynamic([\"AttachUserPolicy\",\"AttachRolePolicy\",\"AttachGroupPolicy\"]);\nlet PolicyArnList = dynamic([\"arn:aws:iam::aws:policy/AdministratorAccess\",\"arn:aws:iam::aws:policy/DatabaseAdministrator\",\"arn:aws:iam::aws:policy/NetworkAdministrator\",\"arn:aws:iam::aws:policy/SystemAdministrator\",\"arn:aws:iam::aws:policy/AmazonS3FullAccess\"]);\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet lookback = starttime - 14d;\n//Creating a temp table of events creating privileged role or users which can later be correlated with suspicious operations.\nlet PrivilegedRoleorUsers = AWSCloudTrail\n| where TimeGenerated >= lookback \n| where EventName in (EventNameList)\n| extend PolicyArn = tostring(parse_json(RequestParameters).policyArn), RoleName = tostring(parse_json(RequestParameters).roleName)\n| where PolicyArn in (PolicyArnList)\n| distinct PolicyArn, UserIdentityType, UserIdentityUserName,RoleName;\n// Joining the list of identities having Privileged roles with the API call AddRoleToInstanceProfile to indentify the instances which may be used by adversaries as pivot point for privilege escalation.\nPrivilegedRoleorUsers\n| join (\nAWSCloudTrail\n| where TimeGenerated between (starttime..endtime)\n| where EventName in (\"AddRoleToInstanceProfile\") \n| extend InstanceProfileName = tostring(parse_json(RequestParameters).InstanceProfileName), RoleName = tostring(parse_json(RequestParameters).roleName)\n| summarize EventCount=count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by EventSource, EventName, UserIdentityType , UserIdentityArn , UserIdentityUserName, SourceIpAddress, RoleName\n) on RoleName \n| extend timestamp = StartTimeUtc, IPCustomEntity = SourceIpAddress, AccountCustomEntity = RoleName\n```"
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

