---
id: 70a6e84f-6f3b-4ce1-83d6-ea6df9e7a9dd
name: Suspicious activity of STS token related to Lambda
description: |
  'Suspicious activity of the STS token of a Lambda function (for example, by SSRF) indicates a possible token hijacking. An attacker may have stolen the token and could abuse its permissions to escalate privileges and move laterally in the cloud account.'
severity: High
requiredDataConnectors:
  - connectorId: AWS
    dataTypes:
      - AWSCloudTrail
tactics:
  - Credential Access
relevantTechniques:
  - T1528
query: "```kusto\nlet aws_public_ips = externaldata(prefixes: string)\n[ \n   h@'https://aka.ms/awspublicipaddresse/aws-public-ip-addresses/ip-ranges.json'\n]\nwith(format='multijson');\nlet timeframe = 30m;\nlet lookback = 12h;\n//Get the AccessKey in the STS token when Lambda service assumes the Role periodically (max assumed session can be 12h)\nlet sts_token = AWSCloudTrail\n| where TimeGenerated >= ago (lookback)\n| where EventSource == \"sts.amazonaws.com\" and SourceIpAddress == \"lambda.amazonaws.com\"\n| extend instanceId = tostring(parse_json(RequestParameters).roleSessionName)\n| extend token = tostring(parse_json(ResponseElements).credentials.accessKeyId);\n//Get the identities who used that STS token - this can be the Lambda function itself which assumed it (legit),\n//but it can also be an external identity which abuses the token permissions\nlet tokenUsage = AWSCloudTrail\n| where TimeGenerated >= ago (timeframe)\n| join kind=inner sts_token on $left.UserIdentityAccessKeyId == $right.token\n| extend region = AWSRegion1\n| project-away SourceIpAddress1, UserIdentityUserName1, UserIdentityArn1, TimeGenerated1;\n//Check whether the called identity is legit\naws_public_ips\n| mv-expand todynamic(prefixes)\n| extend ip_prefix=tostring(todynamic(prefixes.['ip_prefix']))\n| extend region=tostring(todynamic(prefixes.['region']))\n| extend service=tostring(todynamic(prefixes.['service']))\n| project-away prefixes\n| where service == \"AMAZON\" \n| join kind=inner tokenUsage on region\n| where SourceIpAddress !contains \"amazonaws.com\"\n| where ipv4_is_private(SourceIpAddress) == false\n| extend IsInRange = ipv4_is_in_range(SourceIpAddress, ip_prefix)\n| extend UserIdentityUserName = iff(isnotempty(UserIdentityUserName), UserIdentityUserName, tostring(split(UserIdentityArn,'/')[-1]))\n| extend timestamp = TimeGenerated, IPCustomEntity = SourceIpAddress, AccountCustomEntity = UserIdentityUserName, AssumedRoleArn = UserIdentityArn\n| summarize timestamp=arg_max(timestamp,*), r = make_set(IsInRange) by SourceIpAddress, UserIdentityUserName, UserIdentityArn\n| where not (set_has_element(r, true))\n| project-away ip_prefix, IsInRange\n```"
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

