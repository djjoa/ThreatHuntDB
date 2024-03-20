---
id: a2ff777e-46c8-4649-b19a-25a0ac059a18
name: Abnormally Large JPEG Filed Downloaded from New Source
description: |
  'Threat actors can use JPEG files to hide malware, or other malicious code from inspection. This query looks for the downloading of abnormally large JPEG files from a source where large JPEG files have not been downloaded.
    Ref: https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/'
requiredDataConnectors:
  - connectorId: CEF
    dataTypes:
      - CommonSecurityLog
tactics:
  - InitialAccess
relevantTechniques:
  - T1001.002
query: "```kusto\nlet percentile = 95;\n  let lookback_data = materialize(CommonSecurityLog\n  | where TimeGenerated between(ago(7d)..ago(1d))\n  | where FileType == \"Jpeg Files\" or RequestURL endswith \".jpg\"\n  | where isnotempty(RequestURL));\n  let domains = lookback_data | summarize by DestinationHostName;\n  CommonSecurityLog\n  | where TimeGenerated > ago(1d)\n  | where FileType =~ \"Jpeg Files\" or RequestURL endswith \".jpg\"\n  | where isnotempty(RequestURL)\n  | extend filename = split(RequestURL, \"/\")[-1]\n  | where ReceivedBytes > toscalar(lookback_data\n  | summarize percentile(ReceivedBytes, percentile))\n  | project-reorder TimeGenerated, filename, RequestURL, ReceivedBytes, RequestClientApplication, SourceUserName, DestinationHostName, RequestContext \n  | where DestinationHostName !in (domains) or isempty(DestinationHostName)\n```"
entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: filename
  - entityType: Url
    fieldMappings:
      - identifier: Url
        columnName: RequestURL
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: SourceUserName
---

