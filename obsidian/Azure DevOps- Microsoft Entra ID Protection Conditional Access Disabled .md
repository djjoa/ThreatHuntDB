---
id: c78a3845-37d9-448e-a8cd-e9543f00bcc5
name: Azure DevOps- Microsoft Entra ID Protection Conditional Access Disabled
description: |
  'This hunting query identifies Azure DevOps activities where organization Microsoft Entra ID ConditionalAccess policy disable by the admin'
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
  | where OperationName =="OrganizationPolicy.PolicyValueUpdated"
  | where Data.PolicyName == "Policy.EnforceAADConditionalAccess"
  | where Data.PolicyValue == "OFF"
  | extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
  ```
---

