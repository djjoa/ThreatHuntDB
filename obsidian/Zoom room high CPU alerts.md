---
id: 79cf4646-0959-442f-9707-60fc66eb8145
name: Zoom room high CPU alerts
description: |
  'This hunting query identifies Zoom room systems with high CPU alerts that may be a sign of device compromise.'
requiredDataConnectors: []
tactics:
  - DefenseEvasion
  - Persistence
relevantTechniques:
  - T1542
query: "```kusto\n\nZoomLogs \n| where Event =~ \"zoomroom.alert\" \n| extend AlertType = toint(parse_json(RoomEvents).AlertType), AlertKind = toint(parse_json(RoomEvents).AlertKind) \n| extend RoomName = payload_object_room_name_s, User = payload_object_email_s\n| where AlertType == 1 and AlertKind == 1 \n| extend timestamp = TimeGenerated, AccountCustomEntity = User\n// Uncomment the lines below to analyse event over time\n//| summarize count() by bin(TimeGenerated, 1h), RoomName\n//| render timechart\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.0
metadata:
  source:
    kind: Community
  author:
    name: Pete Bryan
  support:
    tier: Community
  categories:
    domains: ["Security - Other"]
---

