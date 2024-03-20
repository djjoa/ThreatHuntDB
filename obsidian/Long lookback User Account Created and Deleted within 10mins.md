---
id: 6135a90e-ba30-4f36-9b6a-3a350050704b
name: Long lookback User Account Created and Deleted within 10mins
description: |
  'User account created and then deleted within 10 minutes across last 14 days'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvent
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098
  - T1078
query: "```kusto\n// TimeDelta is the difference between when the account was created and when it was deleted, default is set to 10min or less\nlet timedelta = 10m;\nSecurityEvent \n// A user account was created\n| where EventID == \"4720\"\n| where AccountType == \"User\"\n| project creationTime = TimeGenerated, CreateEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, \nAccountUsedToCreate = SubjectUserName, TargetSid, SubjectUserSid \n| join kind= inner (\n   SecurityEvent\n   // A user account was deleted \n   | where EventID == \"4726\" \n| where AccountType == \"User\"\n| project deletionTime = TimeGenerated, DeleteEventID = EventID, Activity, Computer, TargetUserName, UserPrincipalName, \nAccountUsedToDelete = SubjectUserName, TargetSid, SubjectUserSid \n) on Computer, TargetUserName\n| where deletionTime - creationTime < timedelta\n| extend TimeDelta = deletionTime - creationTime\n| where tolong(TimeDelta) >= 0\n| project TimeDelta, creationTime, CreateEventID, Computer, TargetUserName, UserPrincipalName, AccountUsedToCreate, \ndeletionTime, DeleteEventID, AccountUsedToDelete\n| extend timestamp = creationTime, HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')), Name = tostring(split(UserPrincipalName, '@', 0)[0]), UPNSuffix = tostring(split(UserPrincipalName, '@', 1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: UPNSuffix
        columnName: UPNSuffix
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
version: 1.0.1
---

