---
id: 43c2832e-6c01-4dc1-bd9e-bc3f330c2b31
name: Excessive number of forbidden requests detected (ASIM Web Session)
description: |
  'This rule detects abnormal number of 403 errors from clients. HTTP 403 is returned when the client is not permitted access to the resource despite providing authentication in case such as when authenticated account not having sufficient permissions'
tags:
  - Schema: WebSession
    SchemaVersion: 0.2.6
requiredDataConnectors: []
tactics:
  - Persistence
  - CredentialAccess
relevantTechniques:
  - T1110
  - T1556
query: |-
  ```kusto
  // Please refer this for more details: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
  let threshold=100; // Update threshold as per your environment
  let lookBack = 1d;
  let ErrorCode=dynamic([403]);
  _Im_WebSession(starttime=ago(lookBack))
  | where EventResultDetails in~ (ErrorCode)
  | summarize ErrorCount = count(), EventStartTime= min(TimeGenerated), EventEndTime=max(TimeGenerated), Urls=make_set(Url,100) by SrcIpAddr, SrcUsername, SrcHostname, DstIpAddr
  | where ErrorCount > threshold
  | extend Name = iif(SrcUsername contains "@", tostring(split(SrcUsername,'@',0)[0]),SrcUsername), UPNSuffix = iif(SrcUsername contains "@",tostring(split(SrcUsername,'@',1)[0]),"")
  | order by ErrorCount desc
  | extend IP_0_Address = SrcIpAddr
  | extend IP_1_Address = DstIpAddr
  | extend Host_0_HostName = SrcHostname
  | extend Account_0_Name = Name
  | extend Account_0_UPNSuffix = UPNSuffix
  ```
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: SrcHostname
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SrcIpAddr
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DstIpAddr
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
version: 1.0.0
---

