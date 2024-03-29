---
id: 1dd98313-f43f-4d8b-9870-5a1dfb2cf93f
name: New client running queries
description: |
  'This hunting query looks for clients running queries that have not previously been seen running queries.'
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
  let lookback = totimespan((endtime-starttime)*7);
  LAQueryLogs
  | where TimeGenerated between (ago(lookback)..starttime)
  | where ResponseCode == 200
  | join kind= rightanti(
  LAQueryLogs
  | where TimeGenerated between(starttime..endtime)
  )
  on RequestClientApp
  | extend timestamp = TimeGenerated, AccountCustomEntity = AADEmail
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

