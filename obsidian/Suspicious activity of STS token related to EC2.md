---
id: 82ecf967-d6e9-4757-8f5d-42c562a8f05f
name: Suspicious activity of STS token related to EC2
description: |
  'Suspicious activity of the STS token of an EC2 machine hosted by ECS (for example, by SSRF) indicates a possible token hijacking. An attacker may have stolen the token and could abuse its permissions to escalate privileges and move laterally in the cloud account.'
severity: High
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Credential Access
relevantTechniques:
  - T1528
query: "```kusto\nlet aws_public_ips = externaldata(prefixes: string)\n[ \n   h@'https://aka.ms/awspublicipaddresse/aws-public-ip-addresses/ip-ranges.json'\n]\nwith(format='multijson');\nlet timeframe = 30m;\nlet lookback = 12h;\n//Get the AccessKey in the STS token (IMDS) when EC2 service assumes the Role periodically\nlet sts_token = AWSCloudTrail\n| where TimeGenerated >= ago (lookback)\n| where EventSource == \"sts.amazonaws.com\" and SourceIpAddress == \"ec2.amazonaws.com\"\n| extend instanceId = tostring(parse_json(RequestParameters).roleSessionName)\n| extend token = tostring(parse_json(ResponseElements).credentials.accessKeyId);\n//Identify if the EC2 belongs to ECS/EKS\nlet typeOfEC2 = AWSCloudTrail\n| where TimeGenerated >= ago (lookback)\n| extend instanceId = tostring(split(UserIdentityPrincipalid, \":\")[1])\n| join sts_token on instanceId\n| where UserAgent !startswith \"kubernetes\" or UserAgent !startswith \"Amazon ECS Agent\"\n| project-away SourceIpAddress1, UserIdentityUserName1, UserIdentityArn1, TimeGenerated1;\n//Get the identities who used that STS token - this can be the EC2 which assumed it (legit),\n//but it can also be an external identity (attacker) which abuses the token permissions \nlet tokenUsage = AWSCloudTrail\n| where TimeGenerated >= ago (timeframe)\n| join kind=inner typeOfEC2 on $left.UserIdentityAccessKeyId == $right.token\n| extend region = AWSRegion\n| project-away SourceIpAddress1, UserIdentityUserName1, UserIdentityArn1, TimeGenerated1;\n//Check whether the called identity is legit\naws_public_ips\n| mv-expand todynamic(prefixes)\n| extend ip_prefix=tostring(todynamic(prefixes.['ip_prefix']))\n| extend region=tostring(todynamic(prefixes.['region']))\n| extend service=tostring(todynamic(prefixes.['service']))\n| project-away prefixes\n| where service == \"EC2\" \n| join kind=inner tokenUsage on region\n| where SourceIpAddress !contains \"amazonaws.com\"\n| where ipv4_is_private(SourceIpAddress) == false\n| extend IsInRange = ipv4_is_in_range(SourceIpAddress, ip_prefix)\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName, AssumedRoleArn = UserIdentityArn\n| summarize timestamp=arg_max(timestamp,*), r = make_set(IsInRange) by SourceIpAddress, UserIdentityUserName, UserIdentityArn\n| where not (set_has_element(r, true))\n| project-away ip_prefix, IsInRange\n```"
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

