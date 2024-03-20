---
id: 8ece8108-7bf7-4571-8f32-ebfd92a6b1ad
name: Beaconing traffic based on common user agents visiting limited number of domains (ASIM Web Session)
description: |
  'This query searches web proxy logs for a specific type of beaconing behavior by caparing with a known request pattern.'
tags:
  - Schema: WebSession
    SchemaVersion: 0.2.6
  - RuleReference: https://github.com/Azure/Azure-Sentinel/blob/f50f90c5e3996507aa1d82fa17a7ac519f41666c/Solutions/FalconFriday/Analytic%20Rules/RecognizingBeaconingTraffic.yaml
requiredDataConnectors: []
tactics:
  - CommandAndControl
relevantTechniques:
  - T1071.001
  - T1571
query: "```kusto\nlet timeframe = 1d; // Timeframe during which to search for beaconing behavior.\nlet lookback = 7d; // lookback period to find if browser was used for other domains by user.\nlet min_requests = 50; // Minimum number of requests to consider it beacon traffic.\nlet min_hours=8; // Minimum number of different hours during which connections were made to consider it beacon traffic.\nlet trusted_user_count=10; // If visited by these many users a domain is considered 'trusted'.\nlet Total_Visited_Sites=3; // Number of different sites visited using this user-agent.\n// Client-specific query to obtain 'browser-like' traffic from proxy logs.\nlet BrowserTraffic = materialize (\n_Im_WebSession(starttime=ago(timeframe))\n| project  TimeGenerated, DestHostname = tostring(parse_url(Url)[\"Host\"]), HttpUserAgent, SrcIpAddr, DstIpAddr\n| where not(ipv4_is_private(DstIpAddr)) // Take only those requests that are going to internet\n| where HttpUserAgent has_any (\"Mozilla\",\"Gecko\")\n);\nlet CommonDomains = BrowserTraffic\n| summarize source_count=dcount(SrcIpAddr) by DestHostname\n| where source_count > trusted_user_count\n| project DestHostname; // These are list of common domains that we will filter out.  \nlet CommonUA = BrowserTraffic\n| summarize source_count=dcount(SrcIpAddr), dhost_count=dcount(DestHostname) by HttpUserAgent\n| where source_count >trusted_user_count and dhost_count > 100 // Normal browsers are used by many people visiting many different sites.\n| project HttpUserAgent;\n// Some users only use the browsers to visit a very limited set of sites.\n// These are considered suspicious, since they might be an attacker masquerading a beacon as a legitimate browser.\nlet SuspiciousClients = BrowserTraffic\n| where HttpUserAgent in (CommonUA)\n| summarize Destination_Hosts = make_set(DestHostname,100), request_count=count() by HttpUserAgent, SrcIpAddr\n| where array_length(Destination_Hosts) <=Total_Visited_Sites and request_count >= min_requests\n| project HttpUserAgent, SrcIpAddr, Destination_Hosts;\n// Just reporting on suspicious browsers gives too many false positives.\n// For example, users that have the browser open on the login screen of 1 specific application.\n// In the suspicious browsers we can search for 'beacon-like' behavior.\n// Get all browser traffic by the suspicious browsers.\nlet PotentialBeaconingTraffic=SuspiciousClients\n| join kind=inner (BrowserTraffic) on HttpUserAgent, SrcIpAddr\n// Find beaconing-like traffic - i.e. contacting the same host in many different hours.\n| summarize hour_count=dcount(bin(TimeGenerated,1h)), Destination_Hosts=take_any(Destination_Hosts), request_count=count() by HttpUserAgent, SrcIpAddr, DestHostname\n| where hour_count >=min_hours and request_count >= min_requests \n// Remove common domains i.e. visited by atleast trusted_user_count number of users.\n| join kind=leftanti CommonDomains on DestHostname // leftanti=> Returns all the records from the left side that don't have matches from the right\n| summarize RareHosts=make_set(DestHostname,100), TotalRequestCount=sum(request_count), BrowserHosts=take_any(Destination_Hosts) by HttpUserAgent, SrcIpAddr\n// Remove browsers that visit any common domains.\n| where array_length(RareHosts) == array_length(BrowserHosts);\n// Look back for X days to see if the browser was not used to visit more hosts.\n// This is to exclude someone that started up the browser a long time ago, and left only a single tab open\nPotentialBeaconingTraffic\n| join kind=inner (_Im_WebSession(starttime=lookback)\n| project  TimeGenerated, DestHostname = tostring(parse_url(Url)[\"Host\"]), HttpUserAgent, SrcIpAddr, DstIpAddr\n| where not(ipv4_is_private(DstIpAddr)) // Take only those requests that are going to internet\n| where HttpUserAgent has_any (\"Mozilla\",\"Gecko\")\n) on SrcIpAddr, HttpUserAgent\n| summarize RareHosts=take_any(RareHosts),BrowserHosts1d=take_any(BrowserHosts),BrowserHostsLookback=make_set(DestHostname,100) by SrcIpAddr, HttpUserAgent\n| where array_length(RareHosts) == array_length(BrowserHostsLookback)\n| extend IP_0_Address = SrcIpAddr\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SrcIpAddr
version: 1.0.0
---
