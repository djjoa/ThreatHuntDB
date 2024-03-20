---
id: 27982ECB-493E-4DAE-BB21-6F0B77B25526
name: Azure secure score one admin
description: "'This query searches for having 1 Global Administrator reduces the surface area of attack for your Azure tenant, \n but sets up a single point of failure for the whole tenant. Global Administrators have access\n to all aspects of Azure'\n"
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
  | where ControlName_s == 'AzureSecureScoreOneAdmin'
  ```
---

