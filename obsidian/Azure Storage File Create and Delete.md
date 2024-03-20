---
id: 276731f6-ae09-4469-9fa0-c0791a5a0d8d
name: Azure Storage File Create and Delete
description: |
  'This hunting query will try to identify instances where a file us uploaded to file storage and then deleted
  within a given threshold. By default the query will find instances where a file is uploaded and deleted within
  5 minutes. This hunting query will help detect automated exfiltration.'
requiredDataConnectors: []
tactics:
  - Exfiltration
relevantTechniques:
  - T1020
  - T1537
tags:
  - Ignite2021
query: "```kusto\n\nlet threshold = 5m;\nlet StorageData =\nunion\nStorageFileLogs,\nStorageBlobLogs;\nStorageData\n| where StatusText =~ \"Success\"\n| where OperationName =~ \"PutBlob\" or OperationName =~ \"PutRange\"\n| extend Uri = tostring(split(Uri, \"?\", 0)[0])\n| join (\n    StorageData\n    | where StatusText =~ \"Success\"\n    | where OperationName =~ \"DeleteBlob\" or OperationName =~ \"DeleteFile\"\n    | extend Uri = tostring(split(Uri, \"?\", 0)[0])\n    | project OperationName, DeletedTime=TimeGenerated, Uri\n) on Uri\n| project TimeGenerated, DeletedTime, Uri, CallerIpAddress, UserAgentHeader, ResponseMd5, StorageAccount=AccountName\n| extend windowEnd = TimeGenerated+5m \n| where DeletedTime between (TimeGenerated .. windowEnd)\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: CallerIpAddress
---

