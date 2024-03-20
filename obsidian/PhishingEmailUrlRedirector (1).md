---
id: 08aff8c6-b983-43a3-be95-68a10c3d35e6
name: PhishingEmailUrlRedirector (1)
description: |
  This query was originally published on Twitter, by @MsftSecIntel.
  The query helps detect emails associated with the open redirector URL campaign. The campaign's URLs begin with the distinct pattern, hxxps://t[.]domain[.]tld/r/?. Attackers use URL redirection to manipulate users into visiting a malicious website or to evade detection.
  Reference - https://twitter.com/MsftSecIntel
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailUrlInfo
tactics:
  - Initial access
query: "```kusto\nEmailUrlInfo\n//This regex identifies emails containing the \"T-Dot\" redirector pattern in the URL\n| where Url matches regex @\"s?\\:\\/\\/(?:www\\.)?t\\.(?:[\\w\\-\\.]+\\/+)+(?:r|redirect)\\/?\\?\" \n    //This regex narrows in on emails that contain the known malicious domain pattern in the URL from the most recent campaigns\n    and Url matches regex @\"[a-zA-Z]\\-[a-zA-Z]{2}\\.(xyz|club|shop)\"\n```"
---

