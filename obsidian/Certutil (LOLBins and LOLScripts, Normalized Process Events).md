---
id: 28233666-c235-4d55-b456-5cfdda29d62d
name: Certutil (LOLBins and LOLScripts, Normalized Process Events)
description: |
  'This detection uses Normalized Process Events to hunt Certutil activities'
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1105
query: "```kusto\nimProcessCreate\n| where Process has \"certutil.exe\"\n// Uncomment the next line and add your commandLine Whitelisted/ignore terms.For example \"urlcache\"\n// | where CommandLine !contains (\"urlcache\") \n| extend HostCustomEntity = Dvc, AccountCustomEntity = User\n```"
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

