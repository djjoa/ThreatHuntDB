---
id: 800ae9c9-0280-4296-821f-c6e0a473fb41
name: Azure DevOps- Public project enabled by admin
description: |
  'This hunting query identifies Azure DevOps activities where organization public projects policy enabled by the admin'
requiredDataConnectors:
  - connectorId: AzureMonitor
    dataTypes:
      - AzureDevOpsAuditing
tactics:
  - Persistence
  - DefenseEvasion
relevantTechniques:
  - T1098
  - T1562
query: |-
  ```kusto
  AzureDevOpsAuditing
  | where OperationName == "OrganizationPolicy.PolicyValueUpdated"
  | where Data.PolicyName == "Policy.AllowAnonymousAccess"
  | where Data.PolicyValue == "ON"
  | extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
  ```
---

