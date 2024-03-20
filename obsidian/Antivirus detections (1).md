---
id: 05250700-5123-45be-826d-dd14c623fade
name: Antivirus detections (1)
description: |
  Query for Microsoft Defender Antivirus detections.
  Query #1: Query for Antivirus detection events.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
query: "```kusto\n// Query #2:\n//    This query select only machines where more than 1 malware family was detected.\n//    Such behavior is usually indicative that some malware was active on the machine\n// Implementation details:\n//    This query looks for alerts on Windows Defender Antivirus detections.\n//    For most purposes it is probably better to query on the events themselves (see query #1).\n//    However, this query might still be useful sometimes (e.g. to quickly parse the family name).\nAlertInfo | join AlertEvidence on AlertId\n| where Title contains \"Defender AV detected\"\n| parse Title with *\"'\"FamilyName\"'\"*\n| summarize FamilyCount=dcount(FamilyName), Families=makeset(FamilyName), Titles=makeset(Title) by DeviceName, DeviceId, bin(Timestamp, 1d)\n| where FamilyCount > 1\n| limit 100 \n```"
---

