---
id: 614a59c5-2dae-4430-bb16-951a28a5f05f
name: Windows System Shutdown/Reboot (Normalized Process Events)
description: |
  'This detection uses Normalized Process Events to detect System Shutdown/Reboot (MITRE Technique: T1529)'
requiredDataConnectors: []
tactics:
  - Impact
relevantTechniques:
  - T1529
query: "```kusto\nlet timeframe = 1d;\nimProcessCreate\n| where Process has \"shutdown.exe\" \n| extend HostCustomEntity = Dvc, AccountCustomEntity = User\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
---

