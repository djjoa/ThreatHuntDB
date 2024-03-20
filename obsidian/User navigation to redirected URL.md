---
id: daf19704-a996-4df7-9a0b-3efac47fea5a
name: User navigation to redirected URL
description: "This query identifies when a user clicks a link that opens a browser to navigate to a URL\nwhich uses redirection. It then filters out any redirections to URLs in the same DNS namespace\nas the originating URL. Redirection identification is done based on URL query parameters \noutlined in the following article: https://www.bleepingcomputer.com/news/security/snapchat-amex-sites-abused-in-microsoft-365-phishing-attacks/\n"
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
tactics:
  - InitialAccess
relevantTechniques:
  - T1566.002
query: "```kusto\nDeviceEvents\n| where ActionType == \"BrowserLaunchedToOpenUrl\"\n| extend ParsedUrl = parse_url(RemoteUrl)\n| extend ParameterKeys = bag_keys(ParsedUrl.['Query Parameters'])\n| mv-apply ParameterKeys to typeof(string) on (\n    where ParameterKeys in~ ('url','redirect','external-link','proxy')\n    | extend ParameterValue = tostring(ParsedUrl.['Query Parameters'].[ParameterKeys])\n    | where ParameterValue startswith \"http\"\n    | extend RedirectedUrl = url_decode(ParameterValue)\n    | extend ParsedRedirectUrl = parse_url(RedirectedUrl)\n)\n| extend \n    OriginalDomain = ParsedUrl.Host, \n    RedirectedDomain = tostring(ParsedRedirectUrl.Host)\n| where \n    OriginalDomain !~ RedirectedDomain \n    and OriginalDomain !endswith '.safelinks.protection.outlook.com'\n| extend \n    oTLD = tostring(split(OriginalDomain, '.')[-1]), \n    oSLD = tostring(split(OriginalDomain, '.')[-2]),\n    rTLD = tostring(split(RedirectedDomain, '.')[-1]), \n    rSLD = tostring(split(RedirectedDomain, '.')[-2])\n| extend \n    OriginalSLD = strcat(oSLD, '.', oTLD), \n    RedirectedSLD = strcat(rSLD, '.', rTLD)\n| project-reorder \n    OriginalDomain, \n    RedirectedDomain, \n    OriginalSLD, \n    RedirectedSLD, \n    RemoteUrl, \n    RedirectedUrl\n```"
---

