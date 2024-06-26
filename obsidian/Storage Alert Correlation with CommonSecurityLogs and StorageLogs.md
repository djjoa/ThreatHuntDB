---
id: 7098cae1-c632-4b40-b715-86d6b07720d7
name: Storage Alert Correlation with CommonSecurityLogs and StorageLogs
description: "'This query combines different Storage alerts with CommonSecurityLogs and StorageLogs helping analysts  triage and investigate any \npossible Storage related attacks faster thus reducing Mean Time To Respond'\n"
requiredDataConnectors:
  - connectorId: AzureSecurityCenter
    dataTypes:
      - SecurityAlert (ASC)
  - connectorId: Fortinet
    dataTypes:
      - CommonSecurityLog
tactics:
  - InitialAccess
  - LateralMovement
relevantTechniques:
  - T1586
  - T1570
query: |-
  ```kusto
  SecurityAlert
  | where DisplayName has_any ("Potential malware uploaded to a storage blob container","Storage account identified as source for distribution of malware")
  | extend Entities = parse_json(Entities)
  | mv-expand Entities
  | where Entities['Type'] =~ "ip"
  | extend AttackerIP = tostring(Entities['Address']), AttackerCountry = tostring(Entities['Location']['CountryName'])
  | join kind=inner (
  union
  StorageFileLogs,
  StorageBlobLogs
  //File upload operations
  | where StatusText =~ "Success"
  | where OperationName =~ "PutBlob" or OperationName =~ "PutRange"
  | extend ClientIP = tostring(CallerIpAddress)
  ) on $left.AttackerIP == $right.ClientIP
  | project AlertTimeGenerated = TimeGenerated, AttackerIP, AttackerCountry
  | join kind=inner (
  CommonSecurityLog
  | where DeviceVendor =~ "Fortinet"
  | where ApplicationProtocol has_any ("SSL","RDP")
  | where LogSeverity has_any ("2","3")
  | where isnotempty(SourceIP) and isnotempty(DestinationIP) and SourceIP != "0.0.0.0"
  | where DeviceAction !in ("close", "client-rst", "server-rst", "deny") and DestinationPort != 161
  | project DeviceProduct,LogSeverity,DestinationPort,DestinationIP,Message,SourceIP,SourcePort,Activity,SentBytes,ReceivedBytes)
   on $left.AttackerIP==$right.DestinationIP
  | summarize count() by AlertTimeGenerated,IpAddress=DestinationIP,SentBytes,ReceivedBytes,AttackerCountry
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
---

