---
id: 7d8692e0-e643-43cb-ac77-6efc5a6b7f4d
name: alt-data-streams
description: |
  This query was originally published in the threat analytics report, Ransomware continues to hit healthcare, critical services. There is also a related blog.
  In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques.
  The following query detects suspicious use of Alternate Data Streams (ADS), which may indicate an attempt to mask malicious activity. These campaigns have been known to deploy ransomware in-memory and exploit ADS.
  The See also section below lists more queries related to techniques shared by these campaigns.
  References:
  https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/
  https://docs.microsoft.com/sysinternals/downloads/streams
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense evasion
query: "```kusto\n// Alternate Data Streams execution \nDeviceProcessEvents \n| where Timestamp > ago(7d) \n// Command lines used \n| where ProcessCommandLine startswith \"-q -s\" and ProcessCommandLine hasprefix \"-p\" \n// Removing IDE processes \nand not(FolderPath has_any(\"visual studio\", \"ide\")) \n| summarize make_set(ProcessCommandLine), make_set(FolderPath), \nmake_set(InitiatingProcessCommandLine) by DeviceId, bin(Timestamp, 1h)\n```"
---

