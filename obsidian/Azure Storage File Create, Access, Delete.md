---
id: 25568c62-414b-4577-acee-5cba9494c232
name: Azure Storage File Create, Access, Delete
description: |
  'This hunting query will identify where a file is uploaded to Azure File or Blob storage
  and is then accessed once before being deleted. This activity may be indicative of
  exfiltration activity.'
requiredDataConnectors: []
tactics:
  - Exfiltration
relevantTechniques:
  - T1537
tags:
  - Ignite2021
query: "```kusto\n\nlet threshold = 5m;\n//Union the file and blob data\nlet StorageData = \nunion\nStorageFileLogs,\nStorageBlobLogs;\n//Get file and blob uploads\nStorageData\n//File upload operations \n| where StatusText =~ \"Success\" \n| where OperationName =~ \"PutBlob\" or OperationName =~ \"PutRange\"\n//Parse the URI to remove the parameters as they change per request \n| extend Uri = tostring(split(Uri, \"?\", 0)[0])\n//Join with deletions, this will return 0 rows if there was no deletion \n| join (\n    StorageData        \n    //File deletion operations     \n    | where OperationName =~ \"DeleteBlob\" or OperationName =~ \"DeleteFile\"     \n    | extend Uri = tostring(split(Uri, \"?\", 0)[0])     \n    | project OperationName, DeletedTime=TimeGenerated, Uri, CallerIpAddress, UserAgentHeader\n    ) on Uri \n| project UploadedTime=TimeGenerated, DeletedTime, OperationName, OperationName1, Uri, UploaderAccountName=AccountName, UploaderIP=CallerIpAddress, UploaderUA=UserAgentHeader, DeletionIP=CallerIpAddress1, DeletionUA=UserAgentHeader1, ResponseMd5\n//Collect file access events where the file was only accessed by a single IP, a single downloader \n| join (\n    StorageData \n    |where Category =~ \"StorageRead\" \n    //File download events \n    | where OperationName =~ \"GetBlob\" or OperationName =~ \"GetFile\"\n    //Again, parse the URI to remove the parameters as they change per request \n    | extend Uri = tostring(split(Uri, \"?\", 0)[0])\n    //Parse the caller IP as it contains the port \n    | extend CallerIpAddress = tostring(split(CallerIpAddress, \":\", 0)[0])\n    //Summarise the download events by the URI, we are only looking for instances where a single caller IP downloaded the file,\n    //so we can safely use any() on the IP. \n    | summarize Downloads=count(), DownloadTimeStart=max(TimeGenerated), DownloadTimeEnd=min(TimeGenerated), DownloadIP=any(CallerIpAddress), DownloadUserAgents=make_set(UserAgentHeader), dcount(CallerIpAddress) by Uri \n    | where dcount_CallerIpAddress == 1\n    ) on Uri \n| project UploadedTime, DeletedTime, OperationName, OperationName1, Uri, UploaderAccountName, UploaderIP, UploaderUA, DownloadTimeStart, DownloadTimeEnd, DownloadIP, DownloadUserAgents, DeletionIP, DeletionUA, ResponseMd5\n| extend timestamp = UploadedTime\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DownloadIP
  - entityType: NetworkConnection
    fieldMappings:
      - identifier: SourceAddress
        columnName: UploaderIP
  - entityType: NetworkConnection
    fieldMappings:
      - identifier: DestinationAddress
        columnName: DownloadIP
---

