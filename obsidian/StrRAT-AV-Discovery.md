---
id: 7ea16edd-7acc-4817-a06d-0e845b4a7260
name: StrRAT-AV-Discovery
description: |
  StrRAT is a Java-based remote access tool which steals browser credentials, logs keystrokes and take remote control of infected systems. It also has a module to download additional payload onto to the infected machine based on C2 server command. Additionally, this threat also has a ransomware encryption/decryption module which appends .crimson extension.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense evasion
query: |-
  ```kusto
  DeviceProcessEvents
  | where InitiatingProcessFileName in~("java.exe", "javaw.exe") and InitiatingProcessCommandLine has "roaming"
  | where FileName == 'cmd.exe' and  ProcessCommandLine has 'path antivirusproduct get displayname'
  ```
---
