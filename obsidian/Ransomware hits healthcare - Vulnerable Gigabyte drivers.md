---
id: 6eade795-7040-48eb-aae7-3f75bf7fad2e
name: Ransomware hits healthcare - Vulnerable Gigabyte drivers
description: |
  Locate vulnerable Gigabyte drivers used by RobbinHood ransomware to turn off security tools.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceFileEvents
query: "```kusto\nDeviceFileEvents \n| where Timestamp > ago(7d) \n| where SHA1 in('0b15b5cc64caf0c6ad9bd759eb35383b1f718edf3d7ab4cd912d0d8c1826edf8', \n'31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427')\n```"
---

