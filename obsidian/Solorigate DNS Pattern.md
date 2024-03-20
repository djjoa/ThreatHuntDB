---
id: 0fb54a5c-5599-4ff9-80a2-f788c3ed285e
name: Solorigate DNS Pattern
description: |
  'Looks for the DGA pattern of the domain associated with Solorigate in order to find other domains with the same activity pattern.'
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\nlet cloudApiTerms = dynamic([\"api\", \"east\", \"west\"]);\nDnsEvents\n| where IPAddresses != \"\" and IPAddresses != \"127.0.0.1\"\n| where Name endswith \".com\" or Name endswith \".org\" or Name endswith \".net\"\n| extend domain_split = split(Name, \".\")\n| where tostring(domain_split[-5]) != \"\" and tostring(domain_split[-6]) == \"\"\n| extend sub_domain = tostring(domain_split[0])\n| where sub_domain !contains \"-\"\n| extend sub_directories = strcat(domain_split[-3], \" \", domain_split[-4])\n| where sub_directories has_any(cloudApiTerms)\n//Based on sample communications the subdomain is always between 20 and 30 bytes\n| where strlen(sub_domain) < 32 and strlen(sub_domain) > 20\n| extend domain = strcat(tostring(domain_split[-2]), \".\", tostring(domain_split[-1])) \n| extend subdomain_no = countof(sub_domain, @\"(\\d)\", \"regex\")\n| extend subdomain_ch = countof(sub_domain, @\"([a-z])\", \"regex\")\n| where subdomain_no > 1\n| extend percentage_numerical = toreal(subdomain_no) / toreal(strlen(sub_domain)) * 100\n| where percentage_numerical < 50 and percentage_numerical > 5\n| summarize count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Name, IPAddresses\n| order by count_ asc\n| extend DNS_0_DomainName = Name\n| extend DNS_0_IpAddress = IPAddresses\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: Name
      - identifier: IpAddress
        columnName: IPAddresses
---

