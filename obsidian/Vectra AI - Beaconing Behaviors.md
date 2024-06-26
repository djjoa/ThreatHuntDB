---
id: b8661942-b3ba-48a4-ae9d-db7c326ebd46
name: Vectra AI - Beaconing Behaviors
description: "'Query searches for beaconing behavior. \nVectra uses its AI to enrich metadata and detect beaconing behaviors within your environment.\nMetadata required = metadata_beacon'\n"
severity: High
requiredDataConnectors:
  - connectorId: AIVectraStream
    dataTypes:
      - VectraStream
tactics:
  - CommandAndControl
relevantTechniques:
  - T1095
  - T1071
  - T1573
  - T1008
  - T1095
  - T1571
  - T1219
tags:
  - DCsync
query: |-
  ```kusto
  //Whitelist source IP (default is empty)
  let whitelist_src_ip = dynamic([""]);
  //Whitelist domain names (default is empty)
  let whitelist_domain = dynamic([""]);
  VectraStream
  | where metadata_type == "metadata_beacon"
  | where id_orig_h !in (whitelist_src_ip) or orig_hostname !in (whitelist_domain)
  | summarize  arg_max(session_count, *) by orig_hostname, id_resp_h
  | project ts, orig_hostname, id_orig_h, id_resp_h, id_resp_p, beacon_type, resp_domains, session_count
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

