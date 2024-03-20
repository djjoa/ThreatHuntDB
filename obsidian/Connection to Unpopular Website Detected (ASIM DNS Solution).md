---
id: 83e70a34-d96f-419d-815b-43d1499e88ed
name: Connection to Unpopular Website Detected (ASIM DNS Solution)
description: |
  'This query lists DNS queries not found in the top 1 million queries in the past 14 days. Please note: To enhance performance, this query uses summarized data if available.'
tags:
  - Schema: ASimDns
    SchemaVersion: 0.1.6
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1095
query: "```kusto\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 1d;\n// calculate avg. eps(events per second)\nlet eps = materialize (_Im_Dns\n  | project TimeGenerated\n  | where TimeGenerated > ago(5m)\n  | count\n  | extend Count = Count / 300);\nlet maxSummarizedTime = toscalar (\n  union isfuzzy=true \n      (\n      DNS_Summarized_Logs_ip_CL \n      | where EventTime_t >= min_t\n      | summarize max_TimeGenerated=max(EventTime_t)\n      | extend max_TimeGenerated = datetime_add('hour', 1, max_TimeGenerated)\n      ),\n      (\n      print(min_t)\n      | project max_TimeGenerated = print_0\n      )\n  | summarize maxTimeGenerated = max(max_TimeGenerated) \n  );\nlet summarizationexist = materialize(\n  union isfuzzy=true \n      (\n      DNS_Summarized_Logs_ip_CL\n      | where EventTime_t > ago(1d) \n      | project v = int(2)\n      ),\n      (\n      print int(1) \n      | project v = print_0\n      )\n  | summarize maxv = max(v)\n  | extend sumexist = (maxv > 1)\n  );\n  let allData = ( union isfuzzy=true\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) > 1000\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(2d)), endtime=ago(dt))\n          | where TimeGenerated > maxSummarizedTime\n          | summarize Count=count() by DnsQuery\n          | top 1000000 by Count\n          | summarize TopOneMillionDNSQuery=make_list(DnsQuery,1000000)\n          | extend exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) between (501 .. 1000)\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(3d)), endtime=ago(dt))\n          | where TimeGenerated > maxSummarizedTime\n          | summarize Count=count() by DnsQuery\n          | top 1000000 by Count\n          | summarize TopOneMillionDNSQuery=make_list(DnsQuery,1000000)\n          | extend exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) <= 500\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(4d)), endtime=ago(dt))\n          | where TimeGenerated > maxSummarizedTime\n          | summarize Count=count() by DnsQuery\n          | top 1000000 by Count\n          | summarize TopOneMillionDNSQuery=make_list(DnsQuery,1000000)\n          | extend exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      DNS_Summarized_Logs_ip_CL\n      | where EventTime_t between (min_t .. ago(dt)) and isnotempty(DnsQuery_s)\n      | project-rename\n          DnsQuery=DnsQuery_s,\n          Count=count__d\n      | extend Count = toint(Count)\n      | summarize TotalCount=toint(sum(Count)) by DnsQuery\n      | top 1000000 by TotalCount\n      | summarize TopOneMillionDNSQuery=make_list(DnsQuery,1000000)\n      )\n      );\n_Im_Dns(starttime=ago(dt),endtime=now())\n| summarize Count=count() by DnsQuery\n| where isnotempty(DnsQuery) and DnsQuery !in (allData)\n| extend DNS_0_DomainName = DnsQuery\n```"
entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: DNSQuery
---

