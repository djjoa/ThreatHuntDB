---
id: 0132d53e-8457-4ed3-b9be-e3ef5ea7d273
name: Dragon Fly
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_dragonfly.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where FileName =~ \"crackmapexec.exe\"\n| top 100 by Timestamp desc\n```"
---

