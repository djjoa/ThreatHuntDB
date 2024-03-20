---
id: f68084a2-87eb-11ec-a8a3-0242ac120002
name: Fake computer account authentication attempt
description: "'This query detects authentication attempt from a fake computer account(username ends with $). \nComputer accounts are normally not authenticating via interactive logon or remote desktop neither they are unlocking the systems.\nRef: https://blog.menasec.net/2019/02/threat-hunting-6-hiding-in-plain-sights.html'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1564
query: |-
  ```kusto
  SecurityEvent
    | where TargetUserName endswith "$" and EventID in (4624,4625) and LogonTypeName in (2,7,10)
    | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by EventID, Computer, TargetUserName, TargetLogonId, LogonTypeName, IpAddress
  ```
---

