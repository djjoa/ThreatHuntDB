---
id: E7BDD9F9-CB83-46E3-9A8E-F14198D3C530
name: Azure secure score block legacy authentication
description: "'This query searches for most compromising sign-in attempts come from legacy authentication. \n Older office clients such as Office 2010 do not support modern authentication \n and use legacy protocols such as IMAP, SMTP, and POP3.'\n"
requiredDataConnectors:
  - connectorId: SenservaPro
    dataTypes:
      - SenservaPro_CL
tactics:
  - CredentialAccess
relevantTechniques:
  - T1212
  - T1556
query: |-
  ```kusto
  let timeframe = 14d;
  SenservaPro_CL
  | where TimeGenerated >= ago(timeframe)
  | where ControlName_s == 'AzureSecureScoreBlockLegacyAuthentication'
  ```
---

