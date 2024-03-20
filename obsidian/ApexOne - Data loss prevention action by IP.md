---
id: 6c7f9bfe-67b5-11ec-90d6-0242ac120003
name: ApexOne - Data loss prevention action by IP
description: |
  'Shows data loss prevention action by IP address.'
severity: Medium
requiredDataConnectors:
  - connectorId: TrendMicroApexOne
    dataTypes:
      - TMApexOneEvent
  - connectorId: TrendMicroApexOneAma
    dataTypes:
      - TMApexOneEvent
tactics:
  - Collection
relevantTechniques:
  - T1213
query: "```kusto\nTMApexOneEvent\n| where TimeGenerated > ago(24h)\n| where EventMessage has \"Data Loss Prevention\"\n| extend DlpAction = case(\nDvcAction == \"-1\", \"Not available\",\nDvcAction == \"0\", \"Blocked\", \nDvcAction == \"1\", \"Deleted\",\nDvcAction == \"2\", \"Delivered\",\nDvcAction == \"3\", \"Logged\", \nDvcAction == \"4\", \"Passed\",\nDvcAction == \"5\", \"Quarantined\",\nDvcAction == \"6\", \"Replaced\", \nDvcAction == \"7\", \"Archived\",\nDvcAction == \"8\", \"Archived (message body only)\",\nDvcAction == \"9\", \"Quarantined (message body only)\", \nDvcAction == \"10\", \"Passed (message body only)\",\nDvcAction == \"11\", \"Encrypted\",\nDvcAction == \"12\", \"Alerted (endpoint)\",\nDvcAction == \"13\", \"Alerted (server)\", \nDvcAction == \"14\", \"Data recorded\",\nDvcAction == \"15\", \"User justified\",\nDvcAction == \"16\", \"Handed off\",\nDvcAction == \"17\", \"Recipient altered\", \nDvcAction == \"18\", \"Blind carbon copied\",\nDvcAction == \"19\", \"Delivery postponed\",\nDvcAction == \"20\", \"Stamped\",\nDvcAction == \"21\", \"Attachment deleted\",\nDvcAction == \"22\", \"Subject tagged\",\nDvcAction == \"23\", \"X-header tagged\",\nDvcAction == \"24\", \"Decrypted\",\nDvcAction == \"25\", \"Re-encrypted\",\nDvcAction == \"26\", \"Tagged (mail)\",\nDvcAction == \"27\", \"Encrypted (user key)\",\nDvcAction == \"28\", \"Encrypted (group key)\",\nDvcAction == \"29\", \"Moved\",\nDvcAction == \"30\", \"Passed (encrypted)\",\nDvcAction == \"31\", \"Passed (user justified)\",\nDvcAction == \"32\", \"Blocked (Endpoint Encryption not installed)\",\nDvcAction == \"33\", \"Blocked (user justified)\",\nDvcAction == \"34\", \"Blocked (Endpoint Encryption logged off)\",\nDvcAction == \"35\", \"Blocked (Endpoint Encryption error)\",\nDvcAction == \"36\", \"web upload\",\n\"unknown\")\n| summarize ActionCount = count() by DlpAction, SrcIpAddr, FileName\n| sort by ActionCount desc \n| extend IPCustomEntity = SrcIpAddr, FileCustomEntity = FileName\n```"
entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPCustomEntity
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileCustomEntity
---

