---
id: 689a9475-440b-4e69-8ab1-a5e241685f39
name: TI Map File Entity to WireData Event
description: |
  'This query finds matches in WireData Event data for known FileName Indicators of Compromise from Threat Intelligence sources. FileName matches may produce false positives, so use this for hunting rather than real-time detection.'
description-detailed: "'This query identifies any matches in the WireData Event data that correspond to any known FileName Indicators of Compromise (IOC) from Threat Intelligence (TI) sources. \nSince file name matches may produce a significant amount of false positives, it is recommended to use this query for hunting purposes rather than for real-time detection.'\n"
requiredDataConnectors:
  - connectorId: AzureMonitor(WireData)
    dataTypes:
      - WireData
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
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet ioc_lookBack = 14d;\nThreatIntelligenceIndicator\n| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()\n| where Active == true\n| where isnotempty(FileName)\n// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated\n| join kind=innerunique (\n  WireData \n  | where TimeGenerated between(starttime..endtime)\n  | where isnotempty(ProcessName)\n  | extend Process =reverse(substring(reverse(ProcessName), 0, indexof(reverse(ProcessName), \"\\\\\")))\n  | extend WireData_TimeGenerated = TimeGenerated\n)\non $left.FileName == $right.Process\n| where WireData_TimeGenerated < ExpirationDateTime\n| summarize WireData_TimeGenerated = arg_max(WireData_TimeGenerated, *) by IndicatorId, Process\n| project WireData_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,\nFileName, Computer, Direction, LocalIP, RemoteIP, LocalPortNumber, RemotePortNumber\n| extend timestamp = WireData_TimeGenerated, HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend IP_0_Address = RemoteIP\n| extend IP_1_Address = LocalIP\n| extend URL_0_Url = Url\n```"
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
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: LocalIP
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Url
version: 1.0.3
---

