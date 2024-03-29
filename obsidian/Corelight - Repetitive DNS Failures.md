---
id: 1ea3a384-77a4-4b0d-8e42-74d26b38ab5b
name: Corelight - Repetitive DNS Failures
description: |
  'Query searches for repetitive DNS resolution failures from single host.'
severity: Medium
requiredDataConnectors:
  - connectorId: Corelight
    dataTypes:
      - Corelight_v2_dns
      - corelight_dns
tactics:
  - CommanAndControl
relevantTechniques:
  - T1094
  - T1043
query: |-
  ```kusto
  let threshold = 100;
  corelight_dns
  | where TimeGenerated > ago(24h)
  | where rcode_name in~ ('NXDOMAIN', 'SERVFAIL')
  | summarize count() by id_orig_h, bin(TimeGenerated, 1h)
  | where count_ > threshold
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: id_orig_h
---

