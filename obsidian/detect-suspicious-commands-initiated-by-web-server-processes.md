---
id: 7fdc5f4a-700d-4713-abfc-181f02968726
name: detect-suspicious-commands-initiated-by-web-server-processes
description: |
  This query was originally published in the threat analytics report, Operation Soft Cell.
  Operation Soft Cell is a series of campaigns targeting users' call logs at telecommunications providers throughout the world. These attacks date from as early as 2012.
  Operation Soft Cell operators sometimes use legitimate web server processes to launch commands, especially for network discovery and user/owner discovery. The following query detects activity of this kind.
  Reference - https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
  - Defense evasion
  - Discovery
query: "```kusto\n// Suspicious commands launched by web server processes\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n// Pivoting on parents or grand parents\nand (((InitiatingProcessParentFileName in(\"w3wp.exe\", \"beasvc.exe\",\n\"httpd.exe\") or InitiatingProcessParentFileName startswith \"tomcat\")\nor InitiatingProcessFileName in(\"w3wp.exe\", \"beasvc.exe\", \"httpd.exe\") or\nInitiatingProcessFileName startswith \"tomcat\"))\n    and FileName in~('cmd.exe','powershell.exe')\n| where ProcessCommandLine contains '%temp%'\n    or ProcessCommandLine has 'wget'\n    or ProcessCommandLine has 'whoami'\n    or ProcessCommandLine has 'certutil'\n    or ProcessCommandLine has 'systeminfo'\n    or ProcessCommandLine has 'ping'\n    or ProcessCommandLine has 'ipconfig'\n    or ProcessCommandLine has 'timeout'\n| summarize any(Timestamp), any(Timestamp), any(FileName),\nmakeset(ProcessCommandLine), any(InitiatingProcessFileName),\nany(InitiatingProcessParentFileName) by DeviceId\n```"
---

