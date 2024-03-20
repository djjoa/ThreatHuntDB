---
id: 3826de45-7300-44d7-800d-a2b457439dda
name: Vectra AI - Suspicious Long DNS Queries
description: |
  'Query searches long DNS queries.
  A high volume of long DNS queries may indicate the usage of DNS Tunneling.
  Metadata required = metadata_dns'
severity: High
requiredDataConnectors:
  - connectorId: AIVectraStream
    dataTypes:
      - VectraStream
tactics:
  - CommandAndControl
  - Exfiltration
relevantTechniques:
  - T1071.004
  - T1048.003
query: "```kusto\nVectraStream\n| where metadata_type == \"metadata_dns\"\n| extend querylength = strlen(['query'])\n| summarize count() by querylength, orig_hostname, id_orig_h\n| sort by querylength desc \n| extend HostCustomEntity = orig_hostname, IPCustomEntity = id_orig_h\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
---

