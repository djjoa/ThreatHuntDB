---
id: 4c17ad45-fe78-4639-98cc-3b2fd173b053
name: Palo Alto Prisma Cloud - Top users by failed logins
description: |
  'Query searches for users who have large number of failed logins.'
severity: Medium
requiredDataConnectors:
  - connectorId: PaloAltoPrismaCloud
    dataTypes:
      - PaloAltoPrismaCloud
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto
  PaloAltoPrismaCloud
  | where TimeGenerated > ago(24h)
  | where ResourceType =~ 'Login'
  | where EventMessage !has 'access key'
  | summarize count() by UserName
  | order by count_ desc
  | extend AccountCustomEntity = UserName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: AccountCustomEntity
---

