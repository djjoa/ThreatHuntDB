---
id: 0ab42aac-2c86-443c-80fa-ef8cdd0d997e
name: GCP IAM - Changed roles
description: |
  'Query searches for roles' modifications.'
severity: Low
requiredDataConnectors:
  - connectorId: GCPIAMDataConnector
    dataTypes:
      - GCP_IAM
tactics:
  - PrivilegeEscalation
relevantTechniques:
  - T1078
query: |-
  ```kusto
  GCP_IAM
  | where TimeGenerated > ago(24h)
  | where PayloadMethodname =~ 'google.iam.admin.v1.UpdateRole'
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

