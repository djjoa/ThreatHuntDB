---
id: 6cb193f3-7c6d-4b53-9153-49a09be830d7
name: Crash dump disabled on host (ASIM Version)
description: |
  'This detection looks the prevention of crash dumps being created. This can be used to limit reporting by malware, look for suspicious processes setting this registry key.'
requiredDataConnectors: []
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1070
query: |-
  ```kusto
  imRegistry
  | where RegistryKey == "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
  | where RegistryValue == "CrashDumpEnabled"
  | where RegistryValueData == 0
  | project-reorder TimeGenerated, RegistryKey, RegistryValue, RegistryValueData, Process, User, ParentProcessName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: User
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: DvcHostname
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Community
  categories:
    domains: ["Security - Threat Protection"]
---

