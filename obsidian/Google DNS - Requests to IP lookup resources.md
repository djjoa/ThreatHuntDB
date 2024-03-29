---
id: 8459cf31-9c5d-48a8-88ca-c4b1a6014031
name: Google DNS - Requests to IP lookup resources
description: |
  'Query searches for requests to IP lookup resources.'
severity: Medium
requiredDataConnectors:
  - connectorId: GCPDNSDataConnector
    dataTypes:
      - GCPCloudDNS
tactics:
  - CommandAndControl
relevantTechniques:
  - T1095
query: |-
  ```kusto
  let ip_check = dynamic(['whatismyipaddress.com', 'ip2location.com', 'ipaddress.my', 'whatismyip.com', 'ipinfo.info', 'checkmyip.com', 'myip.com', 'checkmyip.org', 'canireachthe.net', 'ipv4.icanhazip.com', 'ip.anysrc.net', 'edns.ip-api.com', 'wtfismyip.com', 'checkip.dyndns.org', 'api.2ip.ua', 'icanhazip.com', 'api.ipify.org', 'ip-api.com', 'checkip.amazonaws.com', 'ipecho.net', 'ipinfo.io', 'ipv4bot.whatismyipaddress.com', 'freegeoip.app', 'checkip.azurewebsites.net']);
  GCPCloudDNS
  | where TimeGenerated > ago(24h)
  | where Query in~ (ip_check)
  | extend DNSCustomEntity = Query, IPCustomEntity = SrcIpAddr
  ```
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: DNSCustomEntity
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
---

