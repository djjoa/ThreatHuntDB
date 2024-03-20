---
id: c3b09dd3-ee50-41ae-b863-8603620e5f48
name: Anomalous login activity originated from Botnet, Tor proxy or C2
description: |
  'Shows login activity (successful or failed) originated from botnet, Tor proxy or C2, with at least one 'True' activity insight.'
requiredDataConnectors:
  - connectorId: BehaviorAnalytics
    dataTypes:
      - BehaviorAnalytics
tactics:
relevantTechniques:
query: "```kusto\nBehaviorAnalytics\n| where ActivityType =~ 'LogOn' or ActivityType =~ 'FailedLogOn'\n| where DevicesInsights.ThreatIntelIndicatorType =~ 'Botnet' \n  or DevicesInsights.ThreatIntelIndicatorType =~ 'C2' \n  or DevicesInsights.ThreatIntelIndicatorType =~ 'Proxy'\n| where ActivityInsights contains 'True'\n| extend AadUserId = UsersInsights.AccountObjectID\n| extend Account_0_AadUserId = AadUserId\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: AadUserId
        columnName: AadUserId
version: 2.0.0
---

