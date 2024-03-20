---
id: dde206fc-3f0b-4175-bb5d-42d2aae9d4c9
name: Cobalt Strike DNS Beaconing
description: "'Cobalt Strike is a famous Pen Test tool that is used by pen testers as well as attackers alike To compromise an environment. \n The query tries to detect suspicious DNS queries known from Cobalt Strike beacons.\n"
description-detailed: "'Cobalt Strike is a famous Pen Test tool that is used by pen testers as well as attackers alike To compromise an environment. \n The query tries to detect suspicious DNS queries known from Cobalt Strike beacons.\n This is based out of sigma rules described here: https://github.com/Neo23x0/sigma/blob/master/rules/network/net_mal_dns_cobaltstrike.yml'\n"
requiredDataConnectors:
  - connectorId: DNS
    dataTypes:
      - DnsEvents
  - connectorId: AzureMonitor(VMInsights)
    dataTypes:
      - VMConnection
tactics:
  - CommandAndControl
relevantTechniques:
  - T1568
  - T1008
query: "```kusto\nlet badNames = dynamic([\"aaa.stage.\", \"post.1\"]);\n(union isfuzzy=true\n(DnsEvents \n| where Name has_any (badNames)\n| extend Domain = Name, SourceIp = ClientIP, RemoteIP = todynamic(IPAddresses)\n| mvexpand RemoteIP\n| extend RemoteIP = tostring(RemoteIP)),\n(VMConnection\n| where isnotempty(RemoteDnsCanonicalNames) \n| parse RemoteDnsCanonicalNames with * '[\"' DNSName '\"]' *\n| where DNSName has_any (badNames)\n| extend Domain = DNSName, RemoteIP = RemoteIp\n))\n| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by Domain, SourceIp, RemoteIP, Computer\n| extend timestamp = StartTimeUtc, HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend IP_0_Address = RemoteIP\n```"
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
version: 1.0.1
---

