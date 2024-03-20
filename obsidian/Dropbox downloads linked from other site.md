---
id: de93670b-a1db-4c8c-80aa-5b3146428631
name: Dropbox downloads linked from other site
description: |
  This query looks for user content downloads from dropbox that originate from a link/redirect from a 3rd party site.
  File sharing sites such as Dropbox are often used for hosting malware on a reputable site.
  Read more about download URL data and about this attack vector in this blog post:.
  Https://techcommunity.microsoft.com/t5/Threat-Intelligence/Hunting-tip-of-the-month-Browser-downloads/td-p/220454.
  Tags: #DownloadUrl, #Referer, #Dropbox.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
query: "```kusto\nDeviceFileEvents\n| where \n    Timestamp > ago(7d)\n    and FileOriginUrl startswith \"https://dl.dropboxusercontent.com/\"\n    and isnotempty(FileOriginReferrerUrl)\n    and FileOriginReferrerUrl !startswith \"https://www.dropbox.com/\" \n| project FileOriginReferrerUrl, FileName \n```"
---

