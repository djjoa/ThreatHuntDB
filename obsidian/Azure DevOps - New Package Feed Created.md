---
id: 3d1aa540-b4c7-4789-8c4c-4174b3c2371f
name: Azure DevOps - New Package Feed Created
description: |
  'An attacker could look to introduce upstream compromised software packages by creating a new package feed within Azure DevOps. This query looks for new Feeds and includes details on any Microsoft Entra ID Identity Protection alerts related to the user account creating the feed to assist in triage.'
requiredDataConnectors: []
tactics:
  - InitialAccess
relevantTechniques:
  - T1195
query: |-
  ```kusto
  let alert_threshold = 0;
  AzureDevOpsAuditing
  | where OperationName matches regex "Artifacts.Feed.(Org|Project).Create"
  | extend FeedName = tostring(Data.FeedName)
  | extend FeedId = tostring(Data.FeedId)
  | join kind = leftouter (
  SecurityAlert
  | where ProviderName == "IPC"
  | extend AadUserId = tostring(parse_json(Entities)[0].AadUserId)
  | summarize Alerts=count() by AadUserId) on $left.ActorUserId == $right.AadUserId
  | extend Alerts = iif(isempty(Alerts), 0, Alerts)
  | project-reorder TimeGenerated, Details, ActorUPN, IpAddress, UserAgent
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

