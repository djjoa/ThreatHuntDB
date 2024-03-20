---
id: 8e9c4680-8c0b-4885-b183-3b09efd8fc2c
name: DNS lookups for commonly abused TLDs
description: "'Some top level domains (TLDs) are more commonly associated with malware for a range of \nreasons - including how easy domains on these TLDs are to obtain. Many of these may be undesirable \nfrom an enterprise policy perspective. You can update and extend the list of TLD's  you wish to search for.\nThe NameCount column provides an initial insight into how widespread the domain usage is across the environment.'\n"
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
tactics:
  - CommandAndControl
  - Exfiltration
relevantTechniques:
  - T1568
  - T1008
  - T1048
query: "```kusto\n// Add additional TLDs to this list are required.\nlet abusedTLD = dynamic([\"click\", \"club\", \"download\",  \"xxx\", \"xyz\"]);\nDnsEvents\n| where Name has \".\" \n| extend tld = tostring(split(Name, \".\")[-1])\n| where tld in~ (abusedTLD)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), NameCount = count() by Name, ClientIP, tld\n| order by NameCount desc\n| extend DNS_0_DomainName = Name\n| extend IP_0_Address = ClientIP\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: Name
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
---

