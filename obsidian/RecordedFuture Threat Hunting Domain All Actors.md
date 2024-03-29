---
id: d641a534-ead8-41aa-a7c8-2b35e6b64c9f
name: RecordedFuture Threat Hunting Domain All Actors
description: |
  'Recorded Future Threat Hunting domain correlation for all actors.'
severity: Medium
requiredDataConnectors:
  - connectorId: ThreatIntelligence
    dataTypes:
      - ThreatIntelligenceIndicator
tags:
  - RecordedFuture
query: |-
  ```kusto
  imDns
  | where isnotempty(Domain)
  | join kind=inner (
  ThreatIntelligenceIndicator
  // Only look for IOCs
  | where isnotempty(DomainName)
  // Only look at Recorded Future Threat Hunt Indicators.
  | where Description startswith "Recorded Future - Threat Hunt"
  | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
  | where Active == true and ExpirationDateTime > now()
  ) on $left.Domain == $right.DomainName
  | project Domain, DstIpAddr
  | extend IP_0_Address = DstIpAddr
  | extend DNS_0_DomainName = Domain
  ```
entityMappings:
  - entityType: DNSResolution
    fieldMappings:
      - identifier: DomainName
        columnName: Domain
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: DstIpAddr
---

