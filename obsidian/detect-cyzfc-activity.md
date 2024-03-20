---
id: 43ca7ed8-a655-4e64-8a2a-ef7a56975560
name: detect-cyzfc-activity
description: |
  These queries was originally published in the threat analytics report, Attacks on gov't, think tanks, NGOs.
  As described further in Analysis of cyberattack on U.S. think tanks, non-profits, public sector by unidentified attackers, there was a very large spear-phishing campaign launched in November 2019.
  The attackers would gain access to a target by having the user click on a link to a compromised website and download a .zip archive.
  Once established on a target's device, the attackers used a malicious DLL named cyzfc.dat to execute additional payloads. They would call a function in the malicious DLL via the legitimate Windows process, rundll32.exe, to connect directly to their command-and-control (C2) servers.
  The following queries detect activity associated with the malicious DLL, cyzfc.dat., used in this campaign.
  Reference - https://docs.microsoft.com/windows-server/administration/windows-commands/rundll32
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
      - DeviceProcessEvents
      - DeviceEvents
      - DeviceRegistryEvents
      - DeviceNetworkEvents
      - DeviceImageLoadEvents
tactics:
  - Execution
query: |-
  ```kusto
  // Query 1: Events involving the DLL container
  let fileHash = "9858d5cb2a6614be3c48e33911bf9f7978b441bf";
  find in (DeviceFileEvents, DeviceProcessEvents, DeviceEvents,
  DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents)
  where SHA1 == fileHash or InitiatingProcessSHA1 == fileHash
  | where Timestamp > ago(10d)
  ```
---
