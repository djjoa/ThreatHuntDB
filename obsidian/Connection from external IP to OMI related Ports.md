---
id: 767b8f6d-8029-4c92-afe1-282167d9d49a
name: Connection from external IP to OMI related Ports
description: |
  'This query detects attempts to exploit OMI vulnerability (CVE-2021-38647) by identifying external IP connections to management ports (5985,5986,1270). It uses the imNetworkSession schema and other logs for this purpose.'
description-detailed: "'This query identifies connection attempts from the external IP addresses to the management ports(5985,5986,1270) related to Open Management Infrastructure(OMI). \n OMI is the Linux equivalent of Windows WMI and helps users manage configurations across remote and local environments. \n The query aims to find attacks targeting OMI vulnerability (CVE-2021-38647). The query primarily leverages the Network Session normalization schema(imNetworkSession) \n as well as a few other logs to look for this activity. The Network normalizing parsers can be deployed in a click using an ARM Template shared in the link below:\n Reference: https://techcommunity.microsoft.com/t5/azure-sentinel/hunting-for-omi-vulnerability-exploitation-with-azure-sentinel/ba-p/2764093\n Reference: https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure\n Reference: https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/ASimNetworkSession\n"
requiredDataConnectors:
  - connectorId: AzureNetworkWatcher
    dataTypes:
      - AzureNetworkAnalytics_CL
  - connectorId: AzureMonitor(VMInsights)
    dataTypes:
      - VMConnection
  - connectorId: AzureFirewall
    dataTypes:
      - AzureDiagnostics
tactics:
  - Reconnaissance
  - InitialAccess
relevantTechniques:
  - T1595
  - T1190
tags:
  - OMIGOD
  - CVE-2021-38647
query: "```kusto\nlet Port = dynamic([\"5985\",\"5986\",\"1270\"]); \n(union isfuzzy=true\n(imNetworkSession\n| extend result = ipv4_is_private(SrcIpAddr)\n| where result == 0  and SrcIpAddr != \"127.0.0.1\"\n| where DstPortNumber in (Port)\n| where EventResult != 'Failure'\n| project TimeGenerated, EventProduct, EventResult, SourceIp = SrcIpAddr, DestinationIp = DstIpAddr,Type, Dvc, DestinationPort= DstPortNumber, SrcPortNumber, Protocol = NetworkProtocol, RemoteCountry = SrcGeoCountry, SrcGeoCity, RemoteLatitude = SrcGeoLatitude, RemoteLongitude = SrcGeoLongitude\n| extend Timestamp = TimeGenerated, IPCustomEntity = SourceIp, HostCustomEntity = Dvc \n),\n(VMConnection\n| where Direction == \"inbound\"\n| extend result = ipv4_is_private(SourceIp)\n| where result == 0  and SourceIp != \"127.0.0.1\"\n| where ProcessName == 'omiengine'\n| where DestinationPort in (Port)\n| project TimeGenerated, Computer, Direction, ProcessName, SourceIp, DestinationIp, DestinationPort, Protocol, RemoteCountry, RemoteLatitude, RemoteLongitude, Type\n| extend Timestamp = TimeGenerated, HostCustomEntity = Computer, IPCustomEntity = SourceIp\n),\n(AzureNetworkAnalytics_CL\n| extend result = ipv4_is_private(SrcIP_s) \n| where result == 0 and SrcIP_s != \"127.0.0.1\"\n| where L7Protocol_s has 'wsman'\n| where DestPort_d in (Port)\n| parse VM_s with * '/' VM \n| project TimeGenerated, SourceIp = SrcIP_s, DestinationIp = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRule_s, VM, Type\n| extend Timestamp = TimeGenerated, HostCustomEntity = VM, IPCustomEntity = SourceIp\n),\nAzureDiagnostics\n| where Category == \"AzureFirewallNetworkRule\" and OperationName == \"AzureFirewallNatRuleLog\"\n| parse msg_s with Protocol ' request from ' SourceIp ':' SourcePort ' to ' DestinationIp ':' DestinationPort \" was \" Action \" to \" InternalIP ':' InternalPort\n| where DestinationPort in (Port)\n| project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Protocol, Action, Resource\n| extend Timestamp = TimeGenerated, IPCustomEntity = SourceIp\n)\n```"
version: 1.0.1
---

