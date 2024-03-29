---
id: dbc2438a-0d16-4890-aaae-cbe0dc433b08
name: RecordedFuture Threat Hunting URL All Actors
description: |
  'Recorded Future  URL  Threat Actor Hunt.'
severity: Medium
requiredDataConnectors:
  - connectorId: ThreatIntelligence
    dataTypes:
      - ThreatIntelligenceIndicator
tags:
  - RecordedFuture
query: |-
  ```kusto
  imWebSession
  | where isnotempty(Url)
  | join kind=inner (
  ThreatIntelligenceIndicator
  // Only look for IOCs
  | where isnotempty(Url)
  // Only look at Recorded Future Threat Hunt Indicators.
  | where Description startswith "Recorded Future - Threat Hunt"
  | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
  | where Active == true and ExpirationDateTime > now()
  ) on $left.Url == $right.Url
  | project Url
  | extend URL_0_Url = Url
  ```
entityMappings:
  - entityType: URL
    fieldMappings:
      - identifier: Url
        columnName: Url
---

