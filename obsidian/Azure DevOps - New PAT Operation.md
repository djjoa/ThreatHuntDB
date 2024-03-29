---
id: 5b6ab1d9-018b-46c6-993b-3198626fc54e
name: Azure DevOps - New PAT Operation
description: |
  'PATs are typically used for repeated, programmatic tasks. This query looks for PATs based authentication being used with an Operation not previous associated with PAT based authentication. This could indicate an attacker using a stolen PAT to perform malicious actions.'
requiredDataConnectors: []
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1078
query: |-
  ```kusto

  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = totimespan((endtime-starttime)*10);
  let PAT_Actions = AzureDevOpsAuditing
  | where TimeGenerated > ago(lookback) and TimeGenerated < starttime
  | where AuthenticationMechanism startswith "PAT"
  | summarize by OperationName;
  AzureDevOpsAuditing
  | where TimeGenerated between(starttime..endtime)
  | where AuthenticationMechanism startswith "PAT"
  | where OperationName !in (PAT_Actions)
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

