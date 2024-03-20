---
id: 28ebbb87-535b-4ba0-80f4-6fbf80b7c55a
name: detect-nbtscan-activity
description: |
  This query was originally published in the threat analytics report, Operation Soft Cell.
  Operation Soft Cell is a series of campaigns targeting users' call logs at telecommunications providers throughout the world. These attacks date from as early as 2012.
  Operation Soft Cell operators have been known to run nbtscan.exe, a legitimate MS-DOS command-line tool used to discover any NETBIOS nameservers on a local or remote TCP/IP network.
  The following query detects any nbtscan activity on the system over the past seven days.
  Reference - https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
      - DeviceFileEvents
tactics:
  - Discovery
query: "```kusto\nlet nbtscan = pack_array(\"9af0cb61580dba0e380cddfe9ca43a3e128ed2f8\",\n\"90da10004c8f6fafdaa2cf18922670a745564f45\");\nunion DeviceProcessEvents , DeviceFileEvents \n| where Timestamp > ago(7d)\n| where FileName =~ \"nbtscan.exe\" or SHA1 in (nbtscan)\n| project FolderPath, FileName, InitiatingProcessAccountName,\nInitiatingProcessFileName, ProcessCommandLine, Timestamp\n```"
---

