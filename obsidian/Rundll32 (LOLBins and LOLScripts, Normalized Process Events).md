---
id: 365a889c-ae0f-461d-bdf1-d6ce11d0ef6f
name: Rundll32 (LOLBins and LOLScripts, Normalized Process Events)
description: |
  'This detection uses Normalized Process Events to hunt Signed Binary Proxy Execution: Rundll32 activities'
requiredDataConnectors: []
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1218.011
query: "```kusto\nimProcessCreate\n| where Process has \"rundll32.exe\"\n// Uncomment the next line and add your commandLine Whitelisted/ignore terms.For example \"payload.dll\"\n// | where CommandLine !contains (\"payload.dll\") \n| extend HostCustomEntity = Dvc, AccountCustomEntity = User\n```"
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

