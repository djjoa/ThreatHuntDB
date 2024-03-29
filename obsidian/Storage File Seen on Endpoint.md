---
id: c7f03700-8bbe-4838-9e78-4852ef21609b
name: Storage File Seen on Endpoint
description: |
  'Finds instances where a file uploaded to blob or file storage and it is seen on an endpoint by Microsoft Defender XDR.'
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
tactics:
  - LateralMovement
relevantTechniques:
  - T1570
tags:
  - Ignite2021
query: |-
  ```kusto

  union StorageFileLogs,
  StorageBlobLogs
  //File upload operations
  | where OperationName =~ "PutBlob" or OperationName =~ "PutRange"
  //Parse out the uploader IP
  | extend ClientIP = tostring(split(CallerIpAddress, ":", 0)[0])
  //Extract the filename from the Uri
  | extend FileName = extract(@"\/([\w\-. ]+)\?", 1, Uri)
  //Base64 decode the MD5 filehash, we will encounter non-ascii hex so string operations don't work
  //We can work around this by making it an array then converting it to hex from an int
  | extend base64Char = base64_decode_toarray(ResponseMd5)
  | mv-expand base64Char
  | extend hexChar = tohex(toint(base64Char))
  | extend hexChar = iff(strlen(hexChar) < 2, strcat("0", hexChar), hexChar)
  | extend SourceTable = iff(OperationName has "range", "StorageFileLogs", "StorageBlobLogs")
  | summarize make_list(hexChar) by CorrelationId, ResponseMd5, FileName, AccountName, TimeGenerated, RequestBodySize, ClientIP, SourceTable
  | extend Md5Hash = strcat_array(list_hexChar, "")
  | project-away list_hexChar, ResponseMd5
  | join (
    DeviceFileEvents
    | where ActionType =~ "FileCreated"
    | where isnotempty(MD5)
    | extend p = pack("FileCreateTime", TimeGenerated, "Device", DeviceName, "DeviceId", DeviceId, "FileName", FileName, "InititatingProcess", InitiatingProcessFileName)
    | summarize make_bag(p), dcount(DeviceName) by MD5
  ) on $left.Md5Hash == $right.MD5
  | project TimeGenerated, FileName, FileHashCustomEntity=Md5Hash, AccountName, SourceTable, DevicesImpacted=dcount_DeviceName, Entitites=bag_p
  ```
entityMappings:
  - entityType: FileHash
    fieldMappings:
      - identifier: Algorithm
        columnName: MD5
      - identifier: Value
        columnName: FileHashCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountName
---

