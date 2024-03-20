---
id: 936d985d-f44c-4ec7-81ae-7aa1995f940d
name: reverse-shell-ransomware-macos
description: |
  This query was originally published in the threat analytics report, EvilQuest signals the rise of Mac ransomware.
  As of the time of this writing (October 2020), ransomware designed to target macOS is relatively rare. EvilQuest is one of the few examples of this kind of malware on the platform.
  The query below can help locate a reverse shell established by an attacker. The command the query searches for is associated with, but not definitely indicative of, EvilQuest infections.
  Other queries related to EvilQuest ransomware can be found under the See also section below.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceProcessEvents
tactics:
  - Command and control
query: |-
  ```kusto
  union DeviceFileEvents, DeviceProcessEvents
  | where Timestamp >= ago(7d)
  | where ProcessCommandLine has "bash -i >& /dev/tcp/"
  ```
---
