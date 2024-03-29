---
id: 02e86bf2-172c-4444-ae8e-e94c5ce2bea3
name: Smart Lockouts
description: |
  'Identifies accounts that have been locked out by smart lockout policies. Review this results for patterns that might suggest that a password spray is triggering these smart lockout events.
  Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts#monitoring-for-failed-unusual-sign-ins'
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
tactics:
  - InitialAccess
relevantTechniques:
  - T1078.004
query: |-
  ```kusto
  SigninLogs
  | where ResultType == 50053
  | extend AccountCustomEntity = UserPrincipalName, IPCustomEntity = IPAddress
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

