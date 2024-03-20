---
id: 9ec67c0b-e319-4f1c-bbea-67119d03740a
name: Anomalous Device Models
description: |
  This query finds anomalous models discovered
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceInfo
tactics: []
relevantTechniques: []
query: "```kusto\n// \nlet AnomalousModelCount = 5;\nDeviceInfo\n| summarize arg_max(Timestamp, *) by DeviceId\n| summarize ModelAppearanceCount=dcount(DeviceId) by Model\n| where ModelAppearanceCount < AnomalousModelCount\n```"
---

