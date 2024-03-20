---
id: 8ea80cde-a211-45e3-a7c3-62fae160026c
name: OAuth Apps reading mail both via GraphAPI and directly [Nobelium]
description: |
  As described in previous guidance, Nobelium may re-purpose legitimate existing OAuth Applications in the environment to their own ends. However, malicious activity patterns may be discernable from  legitimate ones.
  The following query returns OAuth Applications that access mail both directly and via Graph, allowing review of whether such dual access methods follow expected use patterns.
  Reference - https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Exfiltration
tags:
  - Nobelium
query: "```kusto\n// Look for OAuth apps reading mail both via GraphAPI, and directly (not via GraphAPI) \n// (one method may be legitimate and one suspect?) \nlet appsReadingMailDirectly = CloudAppEvents \n| where Timestamp >= ago(1h) \n| where ActionType == \"MailItemsAccessed\" \n| where RawEventData has \"AppId\" \n| extend rawData = parse_json(RawEventData) \n| extend AppId = tostring(parse_json(rawData.AppId)) \n| where AppId != \"00000003-0000-0000-c000-000000000000\" \n| summarize by AppId \n| project-rename OAuthAppId = AppId; \nlet appsReadingMailViaGraphAPI = CloudAppEvents \n| where Timestamp >= ago(1h) \n| where ActionType == \"MailItemsAccessed\" \n| where RawEventData has \"ClientAppId\" \n| where RawEventData has \"00000003-0000-0000-c000-000000000000\" // performance check \n| extend rawData = parse_json(RawEventData) \n| extend AppId = tostring(parse_json(rawData.AppId)) \n| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId \n| where AppId == \"00000003-0000-0000-c000-000000000000\" \n| summarize by OAuthAppId; \n// Applications reading mail both directly and via GraphAPI  \n// (one method may be legitimate and one suspect?) \nappsReadingMailDirectly \n| join kind = inner appsReadingMailViaGraphAPI \non OAuthAppId \n| project OAuthAppId \n```"
---

