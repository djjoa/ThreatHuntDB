---
id: 29752996-e85d-4905-a0e1-a7dcdfcda283
name: New domain added to Whitelist
description: |
  'This hunting query identifies new domains added to the domain login whitelist in Zoom.'
requiredDataConnectors: []
tactics:
  - Persistence
relevantTechniques:
  - T1098
query: "```kusto\n\nZoomLogs \n| where Event =~ \"account.settings_updated\"\n| extend NewDomains = columnifexists(\"payload_object_enforce_logon_domains\", \"\")\n| where isnotempty(NewDomains)\n| project TimeGenerated, Event, User, NewDomains\n| extend timestamp = TimeGenerated, AccountCustomEntity = User\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

