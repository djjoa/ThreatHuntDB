---
id: 1a954599-aa03-421d-a35f-dbe18859bdd5
name: PUA ThreatName per Computer
description: |
  Today MDE Alerts do not show PUA/WDAV ThreatName. This is a demonstration of how to get, for example, PUA Threat Names.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceEvents
query: "```kusto\nDeviceEvents\n| where ActionType == \"AntivirusDetection\"\n| extend ParsedFields=parse_json(AdditionalFields)\n| where ParsedFields.ThreatName contains \"PUA\"\n| project DeviceName, FileName, SHA1 , ThreatName=tostring(ParsedFields.ThreatName),\n          WasRemediated=tobool(ParsedFields.WasRemediated),\n          WasExecutingWhileDetected=tobool(ParsedFields.WasExecutingWhileDetected), Timestamp \n```"
---

