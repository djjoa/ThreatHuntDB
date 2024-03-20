---
id: edbeec9f-86b9-475d-8a42-cc7b95ad2baa
name: Squid malformed requests
description: |
  'Malformed web requests are sometimes used for reconnaissance to detect the presence of network security devices.
  Hunting for a large number of requests from a single source may assist in locating compromised hosts. Note: internal sites may
  be detected by this query and may need excluding on a individual basis. This query presumes the default squid log format is
  being used.'
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - Discovery
relevantTechniques:
  - T1046
query: "```kusto\n\nSyslog\n| where ProcessName contains \"squid\"\n| extend URL = extract(\"(([A-Z]+ [a-z]{4,5}:\\\\/\\\\/)|[A-Z]+ )([^ :]*)\",3,SyslogMessage), \n         SourceIP = extract(\"([0-9]+ )(([0-9]{1,3})\\\\.([0-9]{1,3})\\\\.([0-9]{1,3})\\\\.([0-9]{1,3}))\",2,SyslogMessage), \n         Status = extract(\"(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))\",1,SyslogMessage), \n         HTTP_Status_Code = extract(\"(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})\",8,SyslogMessage),\n         User = extract(\"(CONNECT |GET )([^ ]* )([^ ]+)\",3,SyslogMessage),\n         RemotePort = extract(\"(CONNECT |GET )([^ ]*)(:)([0-9]*)\",4,SyslogMessage),\n         Domain = extract(\"(([A-Z]+ [a-z]{4,5}:\\\\/\\\\/)|[A-Z]+ )([^ :\\\\/]*)\",3,SyslogMessage),\n         Bytes = toint(extract(\"([A-Z]+\\\\/[0-9]{3} )([0-9]+)\",2,SyslogMessage)),\n         contentType = extract(\"([a-z/]+$)\",1,SyslogMessage)\n| extend TLD = extract(\"\\\\.[a-z]*$\",0,Domain)\n| where Domain !contains '.' and isnotempty(Domain)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), badRequestCount = count() by Domain, SourceIP, User, URL\n| order by badRequestCount desc\n| extend timestamp = StartTime, AccountCustomEntity = User, IPCustomEntity = SourceIP, URLCustomEntity = URL\n```"
---

