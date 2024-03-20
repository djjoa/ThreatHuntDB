---
id: 172a321b-c46b-4508-87c6-e2691c778107
name: TI Map File Entity to VMConnection Event
description: |
  'This query finds matches in VMConnection Event data for known FileName Indicators of Compromise from Threat Intelligence sources. FileName matches may produce false positives, so use this for hunting rather than real-time detection.'
description-detailed: "'This query identifies any matches in the VMConnection Event data that correspond to any known FileName Indicators of Compromise (IOC) from Threat Intelligence (TI) sources. \nSince file name matches may produce a significant amount of false positives, it is recommended to use this query for hunting purposes rather than for real-time detection.'\n"
requiredDataConnectors:
  - connectorId: AzureMonitor(VMInsights)
    dataTypes:
      - VMConnection
  - connectorId: ThreatIntelligence
    dataTypes:
      - ThreatIntelligenceIndicator
  - connectorId: ThreatIntelligenceTaxii
    dataTypes:
      - ThreatIntelligenceIndicator
  - connectorId: MicrosoftDefenderThreatIntelligence
    dataTypes:
      - ThreatIntelligenceIndicator
tactics:
  - Impact
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet ioc_lookBack = 14d;\nThreatIntelligenceIndicator\n| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()\n| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId\n| where Active == true\n| where isnotempty(FileName)\n| extend TI_ProcessEntity = tostring(split(FileName, \".\")[-2])\n// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated\n| join kind=innerunique (\n  VMConnection \n  | where TimeGenerated between(starttime..endtime)\n  | where isnotempty(ProcessName)\n  | extend VMConnection_TimeGenerated = TimeGenerated\n)\non $left.TI_ProcessEntity == $right.ProcessName\n| where VMConnection_TimeGenerated < ExpirationDateTime\n| summarize VMConnection_TimeGenerated = arg_max(VMConnection_TimeGenerated, *) by IndicatorId, ProcessName\n| project VMConnection_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,\nFileName, Computer, Direction, SourceIp, DestinationIp, RemoteIp, DestinationPort, Protocol\n| extend timestamp = VMConnection_TimeGenerated, HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend IP_0_Address = RemoteIp\n| extend IP_1_Address = SourceIp\n| extend URL_0_Url = Url\n```"
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
        columnName: RemoteIp
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: SourceIp
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Url
version: 1.0.3
---

