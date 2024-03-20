---
id: EF37B9A3-C792-4F2F-8A4E-F8416DE43455
name: Azure Secure Score Self Service Password Reset
description: "'This query searches for requires you to setup Microsoft Entra ID Connect. \n Microsoft Entra ID Connect is free with all Azure Subscriptions'\n"
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
  | where ControlName_s == 'AzureSecureScoreSelfServicePasswordReset'
  ```
---

