---
id: B604620B-0D87-4FFD-BE2E-7E40E81CE559
name: Service principal not using client credentials
description: "'This query searches for an service principal is not using a client certificate or secret is not secure. \n It is recommended that you review your needs and use an Authentication method \n for sign-in.'\n"
requiredDataConnectors:
  - connectorId: SenservaPro
    dataTypes:
      - SenservaPro_CL
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: |-
  ```kusto
  let timeframe = 14d;
  SenservaPro_CL
  | where TimeGenerated >= ago(timeframe)
  | where ControlName_s == 'ServicePrincipalNotUsingClientCredentials'
  ```
---

