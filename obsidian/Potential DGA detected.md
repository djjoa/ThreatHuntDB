---
id: 543e1ec6-ee5e-4368-aaa6-405f0551ba5c
name: Potential DGA detected
description: |
  'Clients with a high NXDomain count could be indicative of a DGA (cycling through possible C2 domains
  where most C2s are not live). Based on quartile percent analysis algorithm.'
severity: Medium
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
queryFrequency: 1d
queryPeriod: 10d
triggerOperator: gt
triggerThreshold: 0
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
  - T1008
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet timeframe = 1d;\nlet excludeTLD = dynamic([\"arris\",\"ati\",\"virtusa\",\"unknowndomain\",\"onion\",\"corp\",\"domain\",\"local\",\"localdomain\",\"host\",\"home\",\"gateway\",\"lan\",\n\"services\",\"hub\",\"domain.name\",\"WirelessAP\",\"Digicom-ADSL\",\"OpenDNS\",\"dlinkrouter\",\"Dlink\",\"ASUS\",\"device\",\"router\",\"Belkin\",\"DHCP\",\"Cisco\"]);\nlet nxDomainDnsEvents = DnsEvents\n| where TimeGenerated between(starttime..endtime)\n| where ResultCode == 3 \n| where QueryType in (\"A\", \"AAAA\")\n| where ipv4_is_match(\"127.0.0.1\", ClientIP) == False\n| where Name !contains \"/\"\n| where Name contains \".\"\n| extend mytld = tostring(split(Name, '.')[-1])\n| where mytld !in~ (excludeTLD)\n| extend truncatedDomain = iff((strlen(Name) - indexof(Name, tostring(split(Name, \".\")[-2])) ) >= 7, \nstrcat(tostring(split(Name, \".\")[-2]), \".\", tostring(split(Name, \".\")[-1])) , \nstrcat(tostring(split(Name, \".\")[-3]), \".\", tostring(split(Name, \".\")[-2]), \".\", tostring(split(Name, \".\")[-1])));\nlet quartileFunctionForIPThreshold = view (mypercentile:long, startTimeSpan:timespan, endTimeSpan:timespan) {\n(nxDomainDnsEvents\n| where TimeGenerated between (ago(startTimeSpan)..ago(endTimeSpan))\n| summarize domainCount = dcount(truncatedDomain) by ClientIP, bin(TimeGenerated, 1d)\n| project SearchList = (domainCount), ClientIP\n| summarize qPercentiles = percentiles(SearchList, mypercentile) by ClientIP);\n};\nlet firstQT = quartileFunctionForIPThreshold(25, 7d, 2d) | project-rename percentile_SearchList_25 = qPercentiles;\nlet thirdQT = quartileFunctionForIPThreshold(75, 7d, 2d) | project-rename percentile_SearchList_75 = qPercentiles;\n// The IP threshold could be adjusted for based on the skewness of the IPthreshold distribution per IP - https://wis.kuleuven.be/stat/robust/papers/2008/outlierdetectionskeweddata-revision.pdf\nlet threshold = (firstQT\n| join thirdQT on ClientIP\n| extend IPthreshold = percentile_SearchList_75 + (1.5*exp(3)*(percentile_SearchList_75 - percentile_SearchList_25))\n| project ClientIP, IPthreshold);\nlet FilterOnIPThreshold_MainTable = (\nnxDomainDnsEvents\n| summarize TotalNXLookups=dcount(truncatedDomain) by ClientIP\n| sort by TotalNXLookups desc\n| join ['threshold'] on ClientIP\n// Comment the line below in order to view results filtered by Global Threshold only. \n| where TotalNXLookups > IPthreshold \n| join kind = leftouter (nxDomainDnsEvents\n    | where TimeGenerated > ago(timeframe)\n    | summarize domainCount = dcount(Name) by truncatedDomain, ClientIP\n    | project SearchList = strcat(truncatedDomain,\" (\",tostring(domainCount),\")\"), ClientIP\n    ) on ClientIP\n| summarize SLDs_DistinctLookups = make_list(SearchList) by ClientIP, TotalNXLookups, IPthreshold\n| sort by TotalNXLookups desc);\n//\nlet quartileFunctionForGlobalThreshold = view (mypercentile:long, startTimeSpan:timespan) {\n(nxDomainDnsEvents\n| where TimeGenerated > ago(startTimeSpan)\n| summarize domainCount = dcount(truncatedDomain) by ClientIP\n| summarize event_count = count() by domainCount\n| summarize perc2 = percentilesw(domainCount, event_count, mypercentile));\n};\nlet firstQ = toscalar(quartileFunctionForGlobalThreshold(25, 1d));\nlet thirdQ = toscalar(quartileFunctionForGlobalThreshold(75, 1d));\n// The Global threshold could be adjusted for based on the skewness of the GlobalThreshold distribution per IP - https://wis.kuleuven.be/stat/robust/papers/2008/outlierdetectionskeweddata-revision.pdf\nlet GlobalThreshold = toscalar(thirdQ + (1.5*exp(3)*(thirdQ - firstQ)));\nlet FilterOnGlobalThreshold_MainTable = (\nnxDomainDnsEvents\n| where TimeGenerated > ago(timeframe)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), TotalNXLookups = dcount(truncatedDomain) by ClientIP\n| sort by TotalNXLookups desc\n// Comment the line below in order to view results filtered by IPThreshold only. \n| where TotalNXLookups > GlobalThreshold \n| join kind = leftouter (nxDomainDnsEvents\n    | where TimeGenerated > ago(timeframe)\n    | summarize domainCount = dcount(Name) by truncatedDomain, ClientIP\n    | project truncatedDomain = strcat(truncatedDomain,\" (\",tostring(domainCount),\")\"), ClientIP\n    ) on ClientIP\n| summarize StartTime = min(StartTime), EndTime = max(EndTime), SLDs_DistinctLookups = make_list(truncatedDomain), UniqueSLDsCount=dcount(truncatedDomain) by ClientIP, TotalNXLookups, GlobalThreshold\n| sort by TotalNXLookups desc);\nFilterOnIPThreshold_MainTable\n| join FilterOnGlobalThreshold_MainTable on ClientIP\n| project StartTime, EndTime, ClientIP, TotalNXLookups, IPthreshold, GlobalThreshold, SLDs_DistinctLookups, UniqueSLDsCount\n| extend IP_0_Address = ClientIP\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: ClientIP
---

