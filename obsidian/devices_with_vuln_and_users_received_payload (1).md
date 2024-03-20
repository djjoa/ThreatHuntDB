---
id: 9c2ba784-c664-40f1-b0df-8f34c6626be5
name: devices_with_vuln_and_users_received_payload (1)
description: |
  // Author: jan geisbauer
  // @janvonkirchheim
  // ---------------------  // 1.	A list of all devices that have this vulnerability
  // 2.	A list of all users that uses those devices
  // 3.	If these users received .mkv files recently
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceTvmSoftwareVulnerabilities
      - DeviceFileEvents
query: "```kusto\n// 1.\tA list of all devices that have this vulnerability\n// 2.\tA list of all users that uses those devices\n// If these users opened those .mkv files\nlet all_computers_with_vlcvln=\nDeviceTvmSoftwareVulnerabilities \n| where SoftwareName contains \"vlc\" \n| summarize makelist(DeviceName);\nDeviceFileEvents \n| where DeviceName  in (all_computers_with_vlcvln)\n| where FileName contains \"mkv\" \n```"
---

