---
id: 85e16874-72aa-4ebe-b36e-e45f8ba50f79
name: Azure Storage file upload from VPS Providers
description: |
  'Looks for file uploads actions to Azure File and Blob Storage from known VPS provider network ranges.
  This is not an exhaustive list of VPS provider ranges but covers some of the most prevalent providers observed.'
requiredDataConnectors: []
tactics:
  - LateralMovement
relevantTechniques:
  - T1570
tags:
  - Ignite2021
query: "```kusto\n\nlet IP_Data = (externaldata(network:string)\n[@\"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/VPS_Networks.csv\"] with (format=\"csv\"));\nunion\nStorageFileLogs,\nStorageBlobLogs\n//File upload operations\n| where StatusText =~ \"Success\"\n| where OperationName =~ \"PutBlob\" or OperationName =~ \"PutRange\"\n| evaluate ipv4_lookup(IP_Data, CallerIpAddress, network, return_unmatched = false)\n| summarize make_set(OperationName), min(TimeGenerated), max(TimeGenerated) by IPCustomEntity=CallerIpAddress, URLCustomEntity=Uri  \n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: URLCustomEntity
---

