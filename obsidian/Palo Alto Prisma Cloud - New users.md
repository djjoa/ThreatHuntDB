---
id: fd92609a-71bd-4da7-8388-e80147757e63
name: Palo Alto Prisma Cloud - New users
description: |
  'Query searches for new users.'
severity: Low
requiredDataConnectors:
  - connectorId: PaloAltoPrismaCloud
    dataTypes:
      - PaloAltoPrismaCloud
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\nlet known_users = \nPaloAltoPrismaCloud\n| where TimeGenerated between (ago(30d) .. (1d))\n| where ResourceType =~ 'Login'\n| where EventMessage !has 'access key'\n| summarize makeset(UserName);\nPaloAltoPrismaCloud\n| where TimeGenerated > ago(24h)\n| where ResourceType =~ 'Login'\n| where EventMessage !has 'access key'\n| where UserName !in (known_users)\n| extend AccountCustomEntity = UserName\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

