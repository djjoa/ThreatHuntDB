---
id: bfb8eaed-941c-4866-a2cc-d5d4465bfc2a
name: RedMenshen-BPFDoor-backdoor
description: |
  This query was originally published by PWC Security Research Team.
  BPFDoor is custom backdoor malware used by Red Menshen. The BPFDoor allows an adversary to backdoor a system and remotely execute codes without opening any new network ports or firewall rules.
References: https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896 https://elastic.github.io/security-research/intelligence/2022/05/04.bpfdoor/article/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
relevantTechniques:
  - T1095
  - T1059.004
  - T1070
query: |-
  ```kusto
  DeviceProcessEvents
  | where InitiatingProcessCommandLine  has ("/dev/shm/kdmtmpflush") or FileName has_any ("haldrund.pid", "kdevrund.pid")
  ```
---

