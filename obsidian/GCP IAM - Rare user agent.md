---
id: ee96562f-cb40-42fd-80d6-dce38cb38f5c
name: GCP IAM - Rare user agent
description: |
  'Query searches for rare user agents.'
severity: Low
requiredDataConnectors:
  - connectorId: GCPIAMDataConnector
    dataTypes:
      - GCP_IAM
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1078
query: "```kusto\nlet known_UAs = \nGCP_IAM\n| where TimeGenerated between (ago(30d) .. (1d))\n| where isnotempty(HttpUserAgentOriginal)\n| summarize makeset(HttpUserAgentOriginal);\nGCP_IAM\n| where TimeGenerated > ago(24h)\n| where isnotempty(HttpUserAgentOriginal)\n| where HttpUserAgentOriginal !in~ (known_UAs)\n| extend timestamp = TimeGenerated, AccountCustomEntity = PayloadRequestAccountId, IPCustomEntity = SrcIpAddr\n```"
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

