---
id: 2bcdf59a-679d-4585-93e7-f14d674de205
name: Abuse.ch Recent Threat Feed
description: |
  This query will hunt for files matching the current abuse.ch recent threat feed based on Sha256. Currently the query is set up to analyze the last day worth of events, but this is configurable using the MaxAge variable.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
      - DeviceFileEvents
      - DeviceImageLoadEvents
tactics:
  - Execution
  - Persistence
  - Privilege escalation
  - Credential Access
  - Discovery
  - Impact
  - Exploit
  - Malware, component
  - Ransomware
query: "```kusto\nlet MaxAge = ago(1d);\nlet AbuseFeed = materialize (\n    (externaldata(report:string)\n    [@\"https://bazaar.abuse.ch/export/csv/recent/\"]\n    with (format = \"txt\"))\n    | where report !startswith '#'\n    | extend report = trim(\"\\\"\", report)\n    | extend report = parse_csv(report)\n    | extend FirstSeenUtc = tostring(report[0])\n    | project FirstSeenUtc = todatetime(FirstSeenUtc)\n        ,SHA256 = trim('[ \"]+',tostring(report[1]))\n        , MD5 = trim('[ \"]+',tostring(report[2]))\n        , SHA1 = trim('[ \"]+',tostring(report[3]))\n        , Reporter = trim('[ \"]+',tostring(report[4]))\n        , FileName = trim('[ \"]+',tostring(report[5]))\n        , FileType = trim('[ \"]+',tostring(report[6]))\n        , MimeType = trim('[ \"]+',tostring(report[7]))\n        , Signer = iff(report[8] == 'n/a', '', trim('[ \"]+',tostring(report[8])))\n        , ClamAV = iff(report[9] == 'n/a', '', trim('[ \"]+',tostring(report[9])))\n        , VTPercent = iff(report[10] == 'n/a', 0.0, todouble(report[10]))\n        , ImpHash = iff(report[11] == 'n/a', '', trim('[ \"]+',tostring(report[11])))\n        , SSDeep = iff(report[12] == 'n/a', '', trim('[ \"]+',tostring(report[12])))\n        , TLSH = iff(report[13] == 'n/a', '', trim('[ \"]+',tostring(report[13])))\n);\nunion (\n    AbuseFeed\n    | join (\n        DeviceProcessEvents\n        | where Timestamp > MaxAge\n    ) on SHA256\n), (\n    AbuseFeed\n    | join (\n        DeviceFileEvents\n        | where Timestamp > MaxAge\n    ) on SHA256\n), ( \n    AbuseFeed\n    | join (\n        DeviceImageLoadEvents\n        | where Timestamp > MaxAge\n        | where isnotempty(SHA256)\n    ) on SHA256\n)\n```"
version: 1.0.0
---

