---
id: 74e8773c-dfa9-45ca-bb60-5d767303e5b3
name: Possible DNS Tunneling or Data Exfiltration Activity (ASIM DNS Solution)
description: |
  'Typical domain name lengths are short, whereas domain name queries used for data exfiltration or tunneling can often be very large in size. The hunting query looks for DNS queries that are more than 150 characters long.'
tags:
  - Schema: ASimDns
    SchemaVersion: 0.1.6
requiredDataConnectors: []
tactics:
  - Exfiltration
relevantTechniques:
  - T1568
  - T1008
  - T1048
query: "```kusto\n// Setting URI length threshold count, shorter URI's may cause noise, change as needed\nlet lookback=1day;\nlet uriThreshold = 150;\nlet ExcludeDomains=dynamic([\"cnr.io\", \"kr0.io\", \"arcticwolf.net\", \"webcfs00.com\", \"barracudabrts.com\", \"trendmicro.com\", \"sophosxl.net\", \n\"spotify.com\", \"e5.sk\", \"mcafee.com\", \"opendns.com\", \"spameatingmonkey.net\", \"_ldap\", \"_kerberos\", \"modsecurity.org\", \n\"fdmarc.net\", \"ipass.com\", \"wpad\"]);\n_Im_Dns(starttime=ago(lookback),endtime=now())\n| summarize count() by SrcIpAddr, DnsQuery\n| where not(DnsQuery has_any (ExcludeDomains))\n| extend Urilength = strlen(DnsQuery)\n| where Urilength >= uriThreshold\n| order by Urilength\n| extend IP_0_Address = SrcIpAddr\n| extend DNS_0_DomainName = DnsQuery\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: DnsQuery
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SrcIpAddr
---

