---
id: 9e8038a8-926f-48cd-9075-5f69b15f5192
name: Vectra AI - Potential Exfiltration over DNS
description: "'Query searches for high volume of DNS resolutions which return non existent domain. \nMetadata required = metadata_dns'\n"
severity: High
requiredDataConnectors:
  - connectorId: AIVectraStream
    dataTypes:
      - VectraStream
tactics:
  - CommandAndControl
  - Exfiltration
relevantTechniques:
  - T1048.003
  - T1071.004
query: |-
  ```kusto
  //Adjust the threshold as desired (default is 500)
  let min_fail_query = 500;
  VectraStream
  | where metadata_type == "metadata_dns"
  | where rcode_name in~ ('NXDOMAIN', 'SERVFAIL')
  | summarize count() by orig_hostname, id_orig_h, bin(TimeGenerated, 1h)
  | where count_ > min_fail_query
  | extend HostCustomEntity = orig_hostname, IPCustomEntity = id_orig_h
  ```
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

