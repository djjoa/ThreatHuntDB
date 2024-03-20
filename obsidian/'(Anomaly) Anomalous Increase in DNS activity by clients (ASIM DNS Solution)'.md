---
id: 50f0cdfb-8b01-4eca-823d-2bbe6b8a5b95
name: '[Anomaly] Anomalous Increase in DNS activity by clients (ASIM DNS Solution)'
description: |
  'Checks for an anomalous increase in DNS activity per client in the last 24 hours as compared to the last 14 days. Please note: To enhance performance, this query uses summarized data if available.'
tags:
  - Schema: ASimDns
    SchemaVersion: 0.1.6
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
  - T1008
  - T1048
query: "```kusto\nlet threshold = 2.5;\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 1d;\n// calculate avg. eps(events per second)\nlet eps = materialize (_Im_Dns\n  | project TimeGenerated\n  | where TimeGenerated > ago(5m)\n  | count\n  | extend Count = Count / 300);\nlet maxSummarizedTime = toscalar (\n  union isfuzzy=true \n      (\n      DNS_Summarized_Logs_ip_CL \n      | where EventTime_t >= min_t\n      | summarize max_TimeGenerated=max(EventTime_t)\n      | extend max_TimeGenerated = datetime_add('hour', 1, max_TimeGenerated)\n      ),\n      (\n      print(min_t)\n      | project max_TimeGenerated = print_0\n      )\n  | summarize maxTimeGenerated = max(max_TimeGenerated) \n  );\nlet summarizationexist = materialize(\n  union isfuzzy=true \n      (\n      DNS_Summarized_Logs_ip_CL\n      | where EventTime_t > ago(1d) \n      | project v = int(2)\n      ),\n      (\n      print int(1) \n      | project v = print_0\n      )\n  | summarize maxv = max(v)\n  | extend sumexist = (maxv > 1)\n  );\nlet allData = union isfuzzy=true\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) > 1000\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(2d)), endtime=now())\n          | where TimeGenerated > maxSummarizedTime and isnotempty(SrcIpAddr)\n          | summarize Count=count() by SrcIpAddr, bin(TimeGenerated, 1h)\n          | extend EventTime = TimeGenerated, Count = toint(Count), exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) between (501 .. 1000)\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(3d)), endtime=now())\n          | where TimeGenerated > maxSummarizedTime and isnotempty(SrcIpAddr)\n          | summarize Count=count() by SrcIpAddr, bin(TimeGenerated, 1h)\n          | extend EventTime = TimeGenerated, Count = toint(Count), exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      (datatable(exists: int, sumexist: bool)[1, false]\n      | where toscalar(eps) <= 500\n      | join (summarizationexist) on sumexist)\n      | join (\n          _Im_Dns(starttime=todatetime(ago(4d)), endtime=now())\n          | where TimeGenerated > maxSummarizedTime and isnotempty(SrcIpAddr)\n          | summarize Count=count() by SrcIpAddr, bin(TimeGenerated, 1h)\n          | extend EventTime = TimeGenerated, Count = toint(Count), exists=int(1)\n          )\n          on exists\n      | project-away exists, maxv, sum*\n      ),\n      (\n      DNS_Summarized_Logs_ip_CL\n      | where EventTime_t > min_t and isnotempty(SrcIpAddr_s)\n      | summarize Count=toint(sum(count__d)) by SrcIpAddr=SrcIpAddr_s, bin(EventTime=EventTime_t, 1h)\n      );\nallData\n| make-series TotalEventCountPerDay= sum(Count) on EventTime from min_t to max_t step dt by SrcIpAddr\n| extend (anomalies, score, baseline) = series_decompose_anomalies(TotalEventCountPerDay, threshold, -1, 'linefit')\n| mv-expand anomalies, score, baseline, EventTime, TotalEventCountPerDay\n| extend\n  anomalies = toint(anomalies),\n  score = toint(score),\n  baseline = toint(baseline),\n  EventTime = todatetime(EventTime),\n  TotalEvents = tolong(TotalEventCountPerDay)\n| where EventTime >= ago(dt)\n| where score >= threshold * 2\n| order by score\n| extend IP_0_Address = SrcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SrcIpAddr
---

