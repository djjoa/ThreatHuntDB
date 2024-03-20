---
id: 6c87bdb8-a44e-452a-b782-542640d985e3
name: DNSPattern [Nobelium]
description: |
  This query looks for the DGA pattern of the domain associated with the Nobelium campaign, in order to find other domains with the same activity pattern.
  This query is inspired by an Azure Sentinel detection.
  Reference - https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Hunting%20Queries/DnsEvents/Solorigate-DNS-Pattern.yaml
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceNetworkEvents
      - DeviceEvents
      - IdentityQueryEvents
tactics:
  - Command and control
tags:
  - Nobelium
query: "```kusto\nlet cloudApiTerms = dynamic([\"api\", \"east\", \"west\"]);\nlet timeFrame = ago(1d);\nlet relevantDeviceNetworkEvents = \n  DeviceNetworkEvents  \n  | where Timestamp >= timeFrame\n  | where RemoteUrl !has \"\\\\\" and RemoteUrl !has \"/\"\n  // performance filter\n  | where RemoteUrl has_any(cloudApiTerms)\n  | project-rename DomainName = RemoteUrl\n  | project Timestamp, DomainName, DeviceId, DeviceName;\nlet relevantDeviceEvents =   \n  DeviceEvents \n  | where Timestamp >= timeFrame\n   | where ActionType == \"DnsQueryResponse\"\n   // performance filter\n   | where AdditionalFields has_any(cloudApiTerms)\n   | extend query = extractjson(\"$.DnsQueryString\", AdditionalFields)  \n   | where isnotempty(query)\n   | project-rename DomainName = query\n   | project Timestamp, DomainName, DeviceId, DeviceName;\nlet relevantIdentityQueryEvents =\n  IdentityQueryEvents \n  | where Timestamp >= timeFrame\n  | where ActionType == \"DNS query\"\n  | where Protocol == \"Dns\"\n  // performance filter\n  | where QueryTarget has_any(cloudApiTerms)\n  | project-rename DomainName = QueryTarget   \n  | project Timestamp, DomainName, DeviceId = \"\", DeviceName;\nlet relevantData =\n  relevantIdentityQueryEvents\n  | union\n  relevantDeviceNetworkEvents  \n  | union\n  relevantDeviceEvents;\nlet tokenCreation =\n  relevantData\n  | extend domain_split = split(DomainName, \".\")\n  | where tostring(domain_split[-5]) != \"\" and tostring(domain_split[-6]) == \"\"\n  | extend sub_domain = tostring(domain_split[0])\n  | where sub_domain !contains \"-\"\n  | extend sub_directories = strcat(domain_split[-3], \" \", domain_split[-4])\n  | where sub_directories has_any(cloudApiTerms);\ntokenCreation\n  //Based on sample communications the subdomain is always between 20 and 30 bytes\n  | where strlen(domain_split) < 32 or strlen(domain_split) > 20\n  | extend domain = strcat(tostring(domain_split[-2]), \".\", tostring(domain_split[-1])) \n  | extend subdomain_no = countof(sub_domain, @\"(\\d)\", \"regex\")\n  | extend subdomain_ch = countof(sub_domain, @\"([a-z])\", \"regex\")\n  | where subdomain_no > 1\n  | extend percentage_numerical = toreal(subdomain_no) / toreal(strlen(sub_domain)) * 100\n  | where percentage_numerical < 50 and percentage_numerical > 5\n  | summarize rowcount = count(), make_set(DomainName), make_set(DeviceId), make_set(DeviceName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DomainName\n  | order by rowcount asc\n```"
---

