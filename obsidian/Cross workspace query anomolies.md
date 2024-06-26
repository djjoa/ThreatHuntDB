---
id: 8f18c6ea-fcd0-4d9a-a8fd-19a6aaa1660c
name: Cross workspace query anomolies
description: |
  'This hunting query looks for increases in the number of workspaces queried by a user.'
requiredDataConnectors:
  - connectorId: AzureMonitor(Query Audit)
    dataTypes:
      - LAQueryLogs
tactics:
  - Collection
  - Exfiltration
relevantTechniques:
  - T1530
  - T1213
  - T1020
query: |-
  ```kusto

  let starttime = todatetime('{{StartTimeISO}}');
  let endtime = todatetime('{{EndTimeISO}}');
  let lookback = starttime - 30d;
  let threshold = 0;
  LAQueryLogs
  | where TimeGenerated between (lookback..starttime)
  | mv-expand(RequestContext)
  | extend RequestContextExtended = split(RequestTarget, "/")
  | extend Subscription = tostring(RequestContextExtended[2]), ResourceGroups = tostring(RequestContextExtended[4]), Workspace = tostring(RequestContextExtended[8])
  | summarize count(), HistWorkspaceCount=dcount(Workspace) by AADEmail
  | join (
  LAQueryLogs
  | where TimeGenerated between(starttime..endtime)
  | mv-expand(RequestContext)
  | extend RequestContextExtended = split(RequestTarget, "/")
  | extend Subscription = tostring(RequestContextExtended[2]), ResourceGroups = tostring(RequestContextExtended[4]), Workspace = tostring(RequestContextExtended[8])
  | summarize make_set(Workspace), count(), CurrWorkspaceCount=dcount(Workspace) by AADEmail
  ) on AADEmail
  | where CurrWorkspaceCount > HistWorkspaceCount
  // Uncomment follow rows to see queries made by these users
  //| join (
  //LAQueryLogs
  //| where TimeGenerated between(starttime..endtime)
  //on AADEmail
  //| extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail
  ```
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Microsoft
  categories:
    domains: ["Security - Threat Protection"]
---

