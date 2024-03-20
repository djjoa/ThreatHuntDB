---
id: 7aaa7675-1580-47d8-a404-039cb7284279
name: Squid commonly abused TLDs
description: "'Some top level domains (TLDs) are more commonly associated with malware for a range of reasons - including how easy domains on these TLDs are to obtain. \nMany of these may be undesirable from an enterprise policy perspective. The clientCount column provides an initial insight into how widespread the domain \nusage is across the estate. This query presumes the default squid log format is being used. http://www.squid-cache.org/Doc/config/access_log/'\n"
requiredDataConnectors:
  - connectorId: Syslog
    dataTypes:
      - Syslog
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
  - T1008
query: "```kusto\n\nlet suspicious_tlds = dynamic([ \".click\", \".club\", \".download\",  \".xxx\", \".xyz\"]);\nSyslog\n| where ProcessName contains \"squid\"\n| extend URL = extract(\"(([A-Z]+ [a-z]{4,5}:\\\\/\\\\/)|[A-Z]+ )([^ :]*)\",3,SyslogMessage), \n         SourceIP = extract(\"([0-9]+ )(([0-9]{1,3})\\\\.([0-9]{1,3})\\\\.([0-9]{1,3})\\\\.([0-9]{1,3}))\",2,SyslogMessage), \n         Status = extract(\"(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))\",1,SyslogMessage), \n         HTTP_Status_Code = extract(\"(TCP_(([A-Z]+)(_[A-Z]+)*)|UDP_(([A-Z]+)(_[A-Z]+)*))/([0-9]{3})\",8,SyslogMessage),\n         User = extract(\"(CONNECT |GET )([^ ]* )([^ ]+)\",3,SyslogMessage),\n         RemotePort = extract(\"(CONNECT |GET )([^ ]*)(:)([0-9]*)\",4,SyslogMessage),\n         Domain = extract(\"(([A-Z]+ [a-z]{4,5}:\\\\/\\\\/)|[A-Z]+ )([^ :\\\\/]*)\",3,SyslogMessage)\n| extend TLD = extract(\"\\\\.[a-z]*$\",0,Domain)\n| where TLD in (suspicious_tlds)\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), clientCount = dcount(SourceIP) by TLD, User, URL\n| order by TLD asc, clientCount desc\n| extend timestamp = StartTime, AccountCustomEntity = User, URLCustomEntity = URL\n```"
---

