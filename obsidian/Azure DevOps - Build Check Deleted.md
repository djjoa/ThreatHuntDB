---
id: 940386c3-4b2c-4147-ac8e-dcddedaaae52
name: Azure DevOps - Build Check Deleted
description: |
  'Build checks can be built into a pipeline in order control the release process, these can include things such as the successful passing of certain steps, or an explicit user approval. An attacker who has altered a build process may look to remove a check in order to ensure a compromised build is released. This hunting query simply looks for all check removal events,  these should be relatively uncommon. In the output Type shows the type of Check that was deleted. '
requiredDataConnectors: []
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1578
query: |-
  ```kusto
  AzureDevOpsAuditing
    | where OperationName =~ "CheckConfiguration.Deleted"
    | extend ResourceName = tostring(Data.ResourceName)
    | extend Type = tostring(Data.Type)
    | project-reorder TimeGenerated, OperationName, ResourceName, Type, ActorUPN, IpAddress, UserAgent
    | extend timestamp = TimeGenerated, AccountCustomEntity = ActorUPN, IPCustomEntity = IpAddress
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

