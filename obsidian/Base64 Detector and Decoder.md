---
id: 89fc1421-8387-4c2b-9bcb-75ead57ccb2c
name: Base64 Detector and Decoder
description: |
  This query will identify strings in process command lines which match Base64 encoding format, extract the string to a column called Base64, and decode it in a column called DecodedString.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
query: "```kusto\nDeviceProcessEvents \n| extend SplitLaunchString = split(ProcessCommandLine, \" \")\n| mvexpand SplitLaunchString\n| where SplitLaunchString matches regex \"^[A-Za-z0-9+/]{50,}[=]{0,2}$\"\n| extend Base64 = tostring(SplitLaunchString)\n| extend DecodedString = base64_decodestring(Base64)\n| where isnotempty(DecodedString)\n```"
---

