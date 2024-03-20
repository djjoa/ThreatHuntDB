---
id: 010d76aa-f2e9-4b88-8134-1ae59655aafe
name: OAuth Apps reading mail via GraphAPI anomaly [Nobelium]
description: |
  Use this query to review OAuth applications whose behaviour has changed as compared to a prior baseline period. The following query returns OAuth Applications accessing user mail via Graph that did not do so in the preceding week.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - CloudAppEvents
tactics:
  - Exfiltration
tags:
  - Nobelium
query: "```kusto\n//Look for OAuth App reading mail via GraphAPI -- that did not read mail via graph API in prior week \nlet appMailReadActivity = (timeframeStart:datetime, timeframeEnd:datetime) { \nCloudAppEvents \n| where Timestamp between (timeframeStart .. timeframeEnd) \n| where ActionType == \"MailItemsAccessed\" \n| where RawEventData has \"00000003-0000-0000-c000-000000000000\" // performance check \n| extend rawData = parse_json(RawEventData) \n| extend AppId = tostring(parse_json(rawData.AppId)) \n| extend OAuthAppId = tostring(parse_json(rawData.ClientAppId)) // extract OAuthAppId \n| summarize by OAuthAppId \n}; \nappMailReadActivity(ago(1d),now())                           // detection period \n| join kind = leftanti appMailReadActivity(ago(7d),ago(2d))  // baseline period \non OAuthAppId \n```"
---

