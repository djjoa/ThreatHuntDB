---
id: AD9CDDB0-6DAA-4616-A397-B9DF7D6082F4
name: Azure secure score role overlap
description: "'This query searches for accounts that have been assigned Global Administrator do not need other roles assigned. \n  Global Administrators have access to all aspects of Azure'\n"
requiredDataConnectors:
  - connectorId: SenservaPro
    dataTypes:
      - SenservaPro_CL
tactics:
  - Impact
relevantTechniques:
  - T1529
query: |-
  ```kusto
  let timeframe = 14d;
  SenservaPro_CL
  | where TimeGenerated >= ago(timeframe)
  | where ControlName_s == 'AzureSecureScoreRoleOverlap'
  ```
---

