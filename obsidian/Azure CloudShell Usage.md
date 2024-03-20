---
id: 42831fb3-f61d-41e9-95d9-f08797479a0e
name: Azure CloudShell Usage
description: |
  'This query look for users starting an Azure CloudShell session and summarizes the Azure Activity from that
  user account during that timeframe (by default 1 hour). This can be used to help identify abuse of the CloudShell
  to modify Azure resources.'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - AuditLogs
tactics:
  - Execution
relevantTechniques:
  - T1059
query: "```kusto\n\nAzureActivity\n   | where ActivityStatusValue =~ \"Success\"\n   | where ResourceGroup has \"cloud-shell-storage\"\n   | where OperationNameValue =~ \"Microsoft.Storage/storageAccounts/listKeys/action\"\n   // Change the timekey scope below to get activity for a longer window \n   | summarize by Caller, timekey= bin(TimeGenerated, 1h)\n   | join (AzureActivity | where TimeGenerated >= ago(1d)\n   | where OperationNameValue !~ \"Microsoft.Storage/storageAccounts/listKeys/action\"\n   | where isnotempty(OperationNameValue)\n    // Change the timekey scope below to get activity for a longer window \n   | summarize make_set(OperationNameValue) by Caller, timekey=bin(TimeGenerated, 1h)) on Caller, timekey\n   | extend timestamp = timekey, AccountCustomEntity = Caller\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

