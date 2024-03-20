---
id: c8a459ae-cb3e-46c0-82b1-670649dd3e7a
name: Hurricane Panda activity
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_hurricane_panda.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where ProcessCommandLine endswith \" localgroup administrators admin /add\"\n     or ProcessCommandLine has @\"\\Win64.exe\"\n| top 100 by Timestamp desc\n```"
---

