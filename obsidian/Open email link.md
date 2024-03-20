---
id: 67be3fdd-6942-45f8-8663-d825b61d1ab9
name: Open email link
description: |
  Query for links opened from mail apps - if a detection occurred right afterwards.
  As there are many links opened from mails, to have a successful hunt we should have some filter or join with some other signal,.
  Such as suspicious processes, network connections, etc.
  Therefore, in this example, we query for alerts that might be related to links sent via email.
  This could be indicative of a phishing or spear-phishing attacks.
  Tags: #EmailLink, #Phishing, #GetNearbyAlerts.
  Explaining the underlying data:.
  This query uses the BrowserLaunchedToOpenUrl event, that includes clicks on http:// or https:// links (clicks outside of browsers), or on .lnk files.
  For this event, RemoteUrl contains the opened URL.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
      - AlertInfo
      - AlertEvidence
query: "```kusto\n// Query for links opened from mail apps - if a detection occurred right afterwards. - MTP Schema\n// As there are many links opened from mails, to have a successful hunt we should have some filter or join with some other signal,\n// such as suspicious processes, network connections, etc.\n// Therefore, in this example, we query for alerts that might be related to links sent via email.\n// This could be indicative of a phishing or spear-phishing attacks.\n// Tags: #EmailLink, #Phishing, #GetNearbyAlerts\n// Explaining the underlying data:\n//     This query uses the BrowserLaunchedToOpenUrl event, that includes clicks on http:// or https:// links (clicks outside of browsers), or on .lnk files\n//     For this event, RemoteUrl contains the opened URL.\nlet minTimeRange = ago(7d);\nlet outlookLinks = \n    DeviceEvents\n    // Filter on click on links from outlook\n    | where Timestamp > minTimeRange and ActionType == \"BrowserLaunchedToOpenUrl\" and isnotempty(RemoteUrl)\n\t| where \n\t\t\t// outlook.exe is the Office Outlook app\n\t\t\tInitiatingProcessFileName =~ \"outlook.exe\" \n\t\t\t// RuntimeBroker.exe opens links for all apps from the Windows store, including the Windows Mail app (HxOutlook.exe).\n\t\t\t// However, it will also include some links opened from other apps.\t\t\t\n\t        or InitiatingProcessFileName =~ \"runtimebroker.exe\"\n    | project Timestamp, DeviceId, DeviceName, RemoteUrl, InitiatingProcessFileName, ParsedUrl=parse_url(RemoteUrl)\n    // When applicable, parse the link sent via email from the clicked O365 ATP SafeLink\n    | extend WasOutlookSafeLink=(tostring(ParsedUrl.Host) endswith \"safelinks.protection.outlook.com\")\n    | project Timestamp, DeviceId, DeviceName, WasOutlookSafeLink, InitiatingProcessFileName,\n            OpenedLink=iff(WasOutlookSafeLink, url_decode(tostring(ParsedUrl[\"Query Parameters\"][\"url\"])), RemoteUrl);\nlet alerts =\n    AlertInfo | join AlertEvidence on AlertId\n    | summarize (FirstDetectedActivity, Title)=argmin(Timestamp, Title) by AlertId, DeviceId\n    // Filter alerts that include events from before the queried time period\n    | where FirstDetectedActivity > minTimeRange;\n// Join the two together - looking for alerts that are right after an abnormal network logon\nalerts | join kind=inner (outlookLinks) on DeviceId | where FirstDetectedActivity - Timestamp between (0min..3min)\n// If there are multiple alerts close to a single click-on-link, aggregate them together to a single row\n// Note: bin(Timestamp, 1tick) is used because when summarizing by a datetime field, the default \"bin\" used is 1-hour.\n| summarize FirstDetectedActivity=min(FirstDetectedActivity), AlertTitles=makeset(Title) by OpenedLink, InitiatingProcessFileName, Timestamp=bin(Timestamp, 1tick), DeviceName, DeviceId, WasOutlookSafeLink\n```"
---

