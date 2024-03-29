---
id: e7642e6e-cf27-46ec-a4b9-e4475228fead
name: AD Account Lockout
description: |
  'Detects Active Directory account lockouts'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Impact
relevantTechniques:
  - T1531
query: |-
  ```kusto
  SecurityEvent
  | where EventID == 4740
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), LockoutsCount = count() by Activity, Account, TargetSid, TargetDomainName, SourceComputerId, SourceDomainController = Computer
  | extend timestamp = StartTime, AccountCustomEntity = Account, HostCustomEntity = TargetDomainName
  ```
---

