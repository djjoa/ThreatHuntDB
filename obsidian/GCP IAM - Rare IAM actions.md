---
id: 85e64fe8-aeed-4021-85de-fdf539917ca1
name: GCP IAM - Rare IAM actions
description: |
  'Query searches for rare IAM actions by users.'
severity: Low
requiredDataConnectors:
  - connectorId: GCPIAMDataConnector
    dataTypes:
      - GCP_IAM
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\nlet user_actions = \nGCP_IAM\n| where TimeGenerated between (ago(30d) .. (1d))\n| where isnotempty(PayloadMethodname)\n| summarize makeset(PayloadMethodname);\nGCP_IAM\n| where TimeGenerated > ago(24h)\n| extend result = parse_json(todynamic(PayloadAuthorizationinfo))[0]['granted']\n| where result =~ 'true'\n| project-away result\n| where PayloadMethodname !in~ (user_actions)\n| extend timestamp = TimeGenerated, AccountCustomEntity = PayloadRequestAccountId, IPCustomEntity = SrcIpAddr\n```"
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

