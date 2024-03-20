---
id: 402b16b9-b41d-477a-9e24-78fc1acdd051
name: Connection to Rare DNS Hosts
description: |
  This query will break down hostnames into their second and third level domain parts and analyze the volume of connections made to the destination to look for low count entries. Note that this query is likely to be rather noisy in many organziations and may benefit from analysis over time, anomaly detection, or perhaps machine learning.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
tactics:
  - Command and control
query: "```kusto\nlet LowCountThreshold = 10;\nlet MaxAge = ago(1d);\nDeviceNetworkEvents\n| where Timestamp > MaxAge\n| where isnotempty( RemoteUrl) and RemoteUrl contains \".\"\n| extend RemoteDomain = iff(RemoteUrl matches regex @'^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}$', tolower(RemoteUrl), tostring(parse_url(RemoteUrl).Host))\n| top-nested 100000 of RemoteDomain by dcount(DeviceId) asc\n| where aggregated_RemoteDomain <= LowCountThreshold \n| join kind=rightsemi (\n    DeviceNetworkEvents\n    | where Timestamp > ago(7d)\n    | where isnotempty( RemoteUrl) and RemoteUrl contains \".\"\n    | extend RemoteDomain = iff(RemoteUrl matches regex @'^([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}$', tolower(RemoteUrl), tostring(parse_url(RemoteUrl).Host))\n) on RemoteDomain \n| extend DomainArray = split(RemoteDomain, '.')\n| extend SecondLevelDomain = strcat(tostring(DomainArray[-2]),'.', tostring(DomainArray[-1])), ThirdLevelDomain = strcat(tostring(DomainArray[-3]), '.', tostring(DomainArray[-2]),'.', tostring(DomainArray[-1]))\n| summarize ConnectionCount = count(), DistinctDevices = dcount(DeviceId) by SecondLevelDomain, ThirdLevelDomain, RemoteDomain\n| where DistinctDevices <= LowCountThreshold \n| top 10000 by DistinctDevices asc\n| order by ConnectionCount asc\n```"
---

