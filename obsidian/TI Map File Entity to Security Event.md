---
id: 233441b9-cc92-4c9b-87fa-73b855fcd4b8
name: TI Map File Entity to Security Event
description: |
  'This query finds matches in Security Event data for known FileName Indicators of Compromise from Threat Intelligence sources. FileName matches may produce false positives, so use this for hunting rather than real-time detection.'
description-detailed: "'This query identifies any matches in the Security Event data that correspond to any known FileName Indicators of Compromise (IOC) from Threat Intelligence (TI) sources. \nSince file name matches may produce a significant amount of false positives, it is recommended to use this query for hunting purposes rather than for real-time detection.'\n"
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
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
query: "```kusto\nlet starttime = todatetime('{{StartTimeISO}}');\nlet endtime = todatetime('{{EndTimeISO}}');\nlet ioc_lookBack = 14d;\nThreatIntelligenceIndicator\n| where TimeGenerated >= ago(ioc_lookBack) and ExpirationDateTime > now()\n| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId\n| where Active == true\n| where isnotempty(FileName)\n| extend _lowerFileName = tolower(FileName)\n// using innerunique to keep perf fast and result set low, we only need one match to indicate potential malicious activity that needs to be investigated\n| join kind=innerunique (\n  SecurityEvent \n  | where TimeGenerated between(starttime..endtime)\n  | where EventID in (\"4688\",\"8002\",\"4648\",\"4673\")\n  | where isnotempty(Process)\n  | extend SecurityEvent_TimeGenerated = TimeGenerated, Event = EventID, _lowerProcess = tolower(Process)\n)\non $left._lowerFileName == $right._lowerProcess\n| where SecurityEvent_TimeGenerated < ExpirationDateTime\n| summarize SecurityEvent_TimeGenerated = arg_max(SecurityEvent_TimeGenerated, *) by IndicatorId, Process\n| project SecurityEvent_TimeGenerated, Description, ActivityGroupNames, IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,\nFileName, Computer, IpAddress, Account, Event, Activity\n| extend timestamp = SecurityEvent_TimeGenerated, NTDomain = split(Account, '\\\\', 0)[0], Name = split(Account, '\\\\', 1)[0], HostName = split(Computer, '.', 0)[0], DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')\n| extend Account_0_Name = Name\n| extend Account_0_NTDomain = NTDomain\n| extend Host_0_HostName = HostName\n| extend Host_0_DnsDomain = DnsDomain\n| extend IP_0_Address = IpAddress\n| extend URL_0_Url = Url\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: Name
        columnName: Name
      - identifier: NTDomain
        columnName: NTDomain
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: HostName
      - identifier: DnsDomain
        columnName: DnsDomain
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Url
version: 1.0.3
---

