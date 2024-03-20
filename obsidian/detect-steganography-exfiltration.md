---
id: e0003bf6-b5f2-4dd1-a130-8651eb0b9f04
name: detect-steganography-exfiltration
description: |
  This query can be used to detect instances of malicious users who attempt to create steganographic images and then immediately browse to a webmail URL.  This query would require additional investigation to determine whether the co-occurrance of generating a steganographic image and browsing to a webmail URL is an indication of a malicious event.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
      - DeviceFileEvents
      - DeviceNetworkEvents
tactics:
  - Exfiltration
query: "```kusto\nlet stegProcesses= view() {\nlet stegnames = pack_array (\"camouflage\",\"crypture\", \"hidensend\", \"openpuff\",\"picsel\",\"slienteye\",\"steg\",\"xiao\");\nlet ProcessQuery = view()\n{\nDeviceProcessEvents\n| where Timestamp > ago(30d)\n| where ProcessCommandLine has_any (stegnames)\n};\nlet FileQuery = view(){\nDeviceFileEvents\n| where FileName has_any (stegnames)\n};\nunion ProcessQuery, FileQuery\n| project StegProcessTimestamp=Timestamp, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine};\nlet WebMailUsage=view(){\n// This query finds network communication to specific webmail URL\nlet webmailURLs = pack_array (\"mail.google.com\", \"mail.yahoo.com\", \"mail.protonmail.com\"); // Change or append additional webmail URLs\nDeviceNetworkEvents \n| where Timestamp > ago(30d)\nand RemoteUrl contains webmailURLs};\nWebMailUsage\n| join stegProcesses on DeviceName\n| where (Timestamp - StegProcessTimestamp) between (0min..30min)\n|project StegProcessTimestamp,Timestamp,RemoteUrl,DeviceName,InitiatingProcessAccountName,FileName\n```"
---

