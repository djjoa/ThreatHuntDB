---
id: 8d69a665-074a-443b-aae6-5dd9bdd5cfb1
name: User Account added to Built in Domain Local or Global Group
description: |
  'User account was added to a privileged built in domain local group or global group such as the Enterprise Adminis, Cert Publishers or DnsAdmins
  Be sure to verify this is an expected addition.'
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
query: "```kusto\n// For AD SID mappings - https://docs.microsoft.com/windows/security/identity-protection/access-control/active-directory-security-groups\nlet WellKnownLocalSID = \"S-1-5-32-5[0-9][0-9]$\";\nlet WellKnownGroupSID = \"S-1-5-21-[0-9]*-[0-9]*-[0-9]*-5[0-9][0-9]$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1102$|S-1-5-21-[0-9]*-[0-9]*-[0-9]*-1103$\";\nSecurityEvent \n| where AccountType == \"User\"\n// 4728 - A member was added to a security-enabled global group\n// 4732 - A member was added to a security-enabled local group\n// 4756 - A member was added to a security-enabled universal group\n| where EventID in (\"4728\", \"4732\", \"4756\")   \n| where TargetSid matches regex WellKnownLocalSID or TargetSid matches regex WellKnownGroupSID\n// Exclude Remote Desktop Users group: S-1-5-32-555\n| where TargetSid !in (\"S-1-5-32-555\")\n| project StartTimeUtc = TimeGenerated, EventID, Activity, Computer, TargetUserName, TargetDomainName, TargetSid, UserPrincipalName, SubjectUserName, SubjectUserSid \n| extend timestamp = StartTimeUtc, HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')), Name = tostring(split(UserPrincipalName, '@', 0)[0]), UPNSuffix = tostring(split(UserPrincipalName, '@', 1)[0])\n| extend Account_0_Name = Name\n| extend Account_0_UPNSuffix = UPNSuffix\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
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

