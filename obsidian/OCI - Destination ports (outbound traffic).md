---
id: fff09b57-24ff-4e47-8a29-6292b0310e19
name: OCI - Destination ports (outbound traffic)
description: |
  'Query searches for destination ports of outbound traffic.'
severity: Low
requiredDataConnectors:
  - connectorId: OracleCloudInfrastructureLogsConnector
    dataTypes:
      - OCILogs
tactics:
  - Exfiltration
relevantTechniques:
  - T1020
query: |-
  ```kusto
  OCILogs
  | where TimeGenerated > ago(24h)
  | where EventType contains 'vcn.flowlogs'
  | where data_action_s =~ 'ACCEPT'
  | where ipv4_is_private(SrcIpAddr)
  | where ipv4_is_private(DstIpAddr) == False
  | summarize count() by SrcIpAddr, DstIpAddr, DstPortNumber
  | extend IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

