---
id: 3e42a796-9a4c-4ebf-a0e0-5282947986b5
name: Corelight - External Facing Services
description: |
  'Query searches for external facing services.'
severity: Low
requiredDataConnectors:
  - connectorId: Corelight
    dataTypes:
      - Corelight_v2_conn
      - corelight_conn
tactics:
  - InitialAccess
relevantTechniques:
  - T1190
  - T1133
query: |-
  ```kusto
  corelight_conn
  | where TimeGenerated > ago(24h)
  | where ipv4_is_private(id_orig_h) == false
  | where isnotempty(id_resp_p)
  | where history startswith 'Sh'
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: id_orig_h
---

