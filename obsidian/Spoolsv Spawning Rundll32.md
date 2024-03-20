---
id: 49fb12a4-f0e9-4f18-a468-9722717774c6
name: Spoolsv Spawning Rundll32
description: |
  Look for the spoolsv.exe launching rundll32.exe with an empty command line
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Privilege escalation
  - Exploit
query: |-
  ```kusto
  DeviceProcessEvents
  | where InitiatingProcessParentFileName has "spoolsv.exe"
  | where InitiatingProcessFileName =~ "rundll32.exe"
  | where isempty(InitiatingProcessCommandLine) or InitiatingProcessCommandLine endswith "rundll32.exe" //either commandline is empty or just "rundll32.exe"
  | where FileName !in~ ("WerFault.exe")
  ```
---
