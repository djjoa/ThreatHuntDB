---
id: b64c8a59-94ad-4659-b95e-36238312da5c
name: Suspicious Image Load related to IcedId
description: |
  Use this query to locate suspicious load image events by rundll32.exe or regsvr32.exe, a behavior associated with IcedId, which can lead to ransomware.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceImageLoadEvents
tactics:
  - Execution
  - Ransomware
query: "```kusto\nDeviceImageLoadEvents \n| where InitiatingProcessFileName in~ ('rundll32.exe','regsvr32.exe') \n| where FileName endswith '.txt' or FileName endswith '.pdf'\n```"
---

