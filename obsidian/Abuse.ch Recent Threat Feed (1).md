---
id: 8bd9e7c0-82b9-43b4-b58e-53d1ee6d9180
name: Abuse.ch Recent Threat Feed (1)
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
query: "```kusto\nlet MaxAge = ago(1d);\nlet AbuseFeed = toscalar (\n    (externaldata(report:string)\n    [@\"https://bazaar.abuse.ch/export/txt/sha256/recent/\"]\n    with (format = \"txt\"))\n    | where report !startswith '#'\n    | summarize make_set(report)\n);\nunion (\n    DeviceProcessEvents\n    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)\n), (\n    DeviceFileEvents\n    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)\n), ( \n    DeviceImageLoadEvents\n    | where Timestamp > MaxAge and SHA256 in (AbuseFeed)\n)\n```"
---

