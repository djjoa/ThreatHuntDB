---
id: 4f0fdeab-1d34-4c1e-9121-8ac800988de8
name: Equation Group C2 Communication
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_equationgroup_c2.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where (FolderPath endswith @\"\\rundll32.exe\" and ProcessCommandLine endswith \",dll_u\") \n        or ProcessCommandLine has \" -export dll_u \"\n| top 100 by Timestamp desc\n```"
---

