---
id: e119c365-9213-45a1-bbd7-8faf6d103d30
name: User denied multiple registration events successfully registering
description: |
  'Query identifies users denied registration for multiple webinars or recordings but successfully registered for at least one event. Threshold variable adjusts number of events user needs to be rejected from.'
description_detailed: |
  'This hunting query identifies users that have attempted to register for multiple webinars or recordings and has been denied by the organizer but have also successfully register for at least one event. The number of events a user needs to be rejected from to be included in this query is adjusted with the threshold variable.'
requiredDataConnectors: []
tactics:
  - InitialAccess
relevantTechniques:
  - T1078
query: "```kusto\n\nlet threshold = 2; \nlet failed_users = (\nZoomLogs \n| where Event =~ \"webinar.registration_denied\" or Event =~ \"recording.registration_denied\" \n| extend RegisteringUser = columnifexists('payload_object_registrant_email_s', payload_object_registrant_email_s)\n| extend ItemId = columnifexists('tostring(parse_json(WebinarEvents).WebinarId)',payload_object_uuid_s)\n| summarize dcount(ItemId) by RegisteringUser\n| where dcount_ItemId > threshold\n| project RegisteringUser);\nZoomLogs \n| where Event =~ \"webinar.registration_approved\" or Event =~ \"recording.registration_approved\" \n| extend RegisteringUser = columnifexists('payload_object_registrant_email_s', columnifexists('payload_object_registrant_email_s', \"\")) \n| extend ItemId = columnifexists('tostring(parse_json(WebinarEvents).WebinarId)',columnifexists('payload_object_uuid_s', \"\"))\n| extend EventName = columnifexists('tostring(parse_json(WebinarEvents).WebinarName)',columnifexists('payload_object_topic_s', \"\"))\n| extend EventHost = columnifexists('payload_object_host_id',\"\")\n| extend EventStart = columnifexists('tostring(parse_json(WebinarEvents).Start)',columnifexists('payload_object_start_time_s' ,\"\"))\n| where RegisteringUser !in (failed_users)\n| project TimeGenerated, RegisteringUser, EventName, ItemId, EventHost, EventStart\n| extend timestamp = TimeGenerated, AccountCustomEntity = RegisteringUser\n```"
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
version: 1.0.1
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
