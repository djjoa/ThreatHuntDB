---
id: a0954a17-cc66-4d47-9651-8bf524bbdcc8
name: Abnormally long DNS URI queries
description: |
  'The length of a DNS query can often be an indicator of suspicious activity. Typical domain name lengths are short, whereas the domain name query used for data exfiltration or tunneling can often be very large in size. This is because they could be encoded using base 64/32 etc. The hunting query looks for Names that are more than 150 characters in length. Due to a lot of services using long DNS to communicate via procedurally generated long domain names,
  this can be problematic, so a number of known services are excluded from this query. Additional items might need to be added to this exclusion, depending on your
  environment.'
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
query: "```kusto\n// Setting URI length threshold count, shorter URI's may cause noise, change as needed\nlet uriThreshold = 150;\nlet LocalDomains = \n(\nDnsEvents\n| summarize count() by Computer \n| extend SubDomain = tolower(strcat(tostring(split(Computer, \".\")[-2]),\".\", tostring(split(Computer, \".\")[-1])))\n| distinct SubDomain\n);\nlet DomainLookups =\n(\nDnsEvents\n| where SubType =~ \"LookupQuery\"\n| where ipv4_is_match(\"127.0.0.1\", ClientIP) == False \n| where Name !endswith \".local\" and Name !startswith \"_\" and Name !startswith \"#\"\n| where Name !contains \"::1\"\n| where Name !has \"cnr.io\" and Name !has \"kr0.io\" and Name !has \"arcticwolf.net\" and Name !has \"webcfs00.com\" and Name !has \"barracudabrts.com\"and Name !has \"trendmicro.com\" \nand Name !has \"sophosxl.net\" and Name !has \"spotify.com\" and Name !has \"e5.sk\" and Name !has \"mcafee.com\" and Name !has \"opendns.com\"  and Name !has \"spameatingmonkey.net\" \nand Name !has \"_ldap\" and Name !has \"_kerberos\" and Name !has \"modsecurity.org\" and Name !has \"fdmarc.net\" and Name !has \"ipass.com\" and Name !has \"wpad\"\nand Name !has \"cnr.io\" and Name !has \"trendmicro.com\" and Name !has \"sophosxl.net\" and Name !has \"spotify.com\" and Name !has \"e5.sk\" and Name !has \"mcafee.com\" \nand Name !has \"opendns.com\"  and Name !has \"spameatingmonkey.net\" and Name !has \"_ldap\" and Name !has \"_kerberos\" and Name !has \"modsecurity.org\" and Name !has \"fdmarc.net\" \nand Name !has \"ipass.com\"\n| extend Name = tolower(Name), Urilength = strlen(Name) \n| where Urilength >= uriThreshold\n| extend SubDomain = case(\nisempty(Name), Name,\narray_length(split(Name, \".\")) <= 2, Name,\ntostring(split(Name, \".\")[-2]) == \"corp\", strcat(tostring(split(Name, \".\")[-3]),\".\",tostring(split(Name, \".\")[-2]),\".\", tostring(split(Name, \".\")[-1])),\nstrlen(tostring(split(Name, \".\")[-1])) == 2, strcat(tostring(split(Name, \".\")[-3]),\".\",tostring(split(Name, \".\")[-2]),\".\", tostring(split(Name, \".\")[-1])),\ntostring(split(Name, \".\")[-2]) != \"corp\", strcat(tostring(split(Name, \".\")[-2]),\".\", tostring(split(Name, \".\")[-1])),\nName))\n;\nDomainLookups\n| join kind= leftanti (\n    LocalDomains\n) on SubDomain \n| summarize by TimeGenerated, Computer, ClientIP, Name, Urilength\n| extend HostName = iff(Computer has '.', substring(Computer,0,indexof(Computer,'.')),Computer)\n| extend DnsDomain = iff(Computer has '.', substring(Computer,indexof(Computer,'.')+1),\"\")\n| extend DNS_0_DomainName = Name\n| extend IP_0_Address = ClientIP\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: Name
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
---

