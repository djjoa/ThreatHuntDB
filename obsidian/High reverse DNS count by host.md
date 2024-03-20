---
id: fda90754-4e22-4bb1-8b99-2bb49a991eae
name: High reverse DNS count by host
description: |
  'Clients with a high reverse DNS count could be carrying out reconnaissance or discovery activity.'
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
tactics:
  - Discovery
relevantTechniques:
  - T1046
query: "```kusto\nlet threshold = 10;\nDnsEvents\n| where Name has \"in-addr.arpa\" \n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), NameCount = dcount(Name), Names = make_set(Name,100), EventCount = count() by ClientIP\n| where NameCount > threshold\n| extend IP_0_Address = ClientIP\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
---

