---
id: a09e6368-065b-4f1e-a4ce-b1b3a64b493b
name: Creation of an anomalous number of resources
description: |
  'Looks for anomalous number of resources creation or deployment activities in azure activity log.
  It is best to run this query on a look back period which is at least 7 days.'
requiredDataConnectors:
  - connectorId: AzureActivity
    dataTypes:
      - AzureActivity
tactics:
  - Impact
relevantTechniques:
  - T1496
query: "```kusto\nAzureActivity\n| where OperationNameValue in~ (\"microsoft.compute/virtualMachines/write\", \"microsoft.resources/deployments/write\")\n| where ActivityStatusValue == \"Succeeded\" \n| make-series dcount(ResourceId)  default=0 on EventSubmissionTimestamp in range(ago(7d), now(), 1d) by Caller\n| extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Caller,'@',1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
version: 2.0.1
---

