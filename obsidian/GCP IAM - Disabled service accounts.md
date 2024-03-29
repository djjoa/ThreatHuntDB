---
id: f228b2ca-3604-475a-8bd1-33b6c5dbcd3d
name: GCP IAM - Disabled service accounts
description: |
  'Query searches for service accounts disabled for the last 24 hours.'
severity: Low
requiredDataConnectors:
  - connectorId: GCPIAMDataConnector
    dataTypes:
      - GCP_IAM
tactics:
  - Impact
relevantTechniques:
  - T1531
query: |-
  ```kusto
  GCP_IAM
  | where TimeGenerated > ago(24h)
  | where PayloadMethodname =~ 'google.iam.admin.v1.DisableServiceAccount'
  | extend result = parse_json(todynamic(PayloadAuthorizationinfo))[0]['granted']
  | where result =~ 'true'
  | project-away result
  | extend timestamp = TimeGenerated, AccountCustomEntity = PayloadRequestAccountId, IPCustomEntity = SrcIpAddr
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

