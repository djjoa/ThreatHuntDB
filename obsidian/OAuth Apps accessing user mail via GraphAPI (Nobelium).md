---
id: 19cbed50-3554-44ed-b8de-90f275b69c8a
name: OAuth Apps accessing user mail via GraphAPI [Nobelium]
description: |
  This query helps you review all OAuth applications accessing user mail via Graph. It could return a significant number of results depending on how many applications are deployed in the environment.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Exfiltration
tags:
  - Nobelium
query: "```kusto\nCloudAppEvents \n| where Timestamp >= ago(1h) \n| where ActionType == \"MailItemsAccessed\" \n| where RawEventData has \"00000003-0000-0000-c000-000000000000\" // performance \n| where RawEventData has \"ClientAppId\" \n| extend rawData = parse_json(RawEventData) \n| extend AppId = tostring(parse_json(rawData.AppId)) \n| where AppId == \"00000003-0000-0000-c000-000000000000\"         // graph API \n| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId \n| summarize by OAuthAppId \n```"
---

