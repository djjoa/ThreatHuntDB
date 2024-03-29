---
id: 9fd6f61d-2cc3-48de-acf5-7194e78d6ea1
name: Windows System Time changed on hosts
description: |
  'Identifies when the system time was changed on a Windows host which can indicate potential timestomping activities.'
description-detailed: |
  'Identifies when the system time was changed on a Windows host which can indicate potential timestomping activities.
  Reference: Event ID 4616 is only available when the full event collection is enabled - https://docs.microsoft.com/azure/sentinel/connect-windows-security-events'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1070
query: |-
  ```kusto
  SecurityEvent
  | where EventID == 4616
  | where not(ProcessName has_any (":\\Windows\\System32\\svchost.exe", ":\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"))
  | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Computer, EventID, Activity, Account, AccountType, NewTime, PreviousTime, ProcessName, ProcessId, SubjectAccount, SubjectUserSid, SourceComputerId, _ResourceId
  | extend timestamp = StartTime, NTDomain = tostring(split(SubjectAccount, '\\', 0)[0]), Name = tostring(split(SubjectAccount, '\\', 1)[0]), HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
  | extend Account_0_Name = Name
  | extend Account_0_NTDomain = NTDomain
  | extend Host_0_HostName = HostName
  | extend Host_0_DnsDomain = DnsDomain
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.2
---

