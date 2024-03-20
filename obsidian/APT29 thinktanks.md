---
id: 40446d6e-745d-4689-a477-6b6a43a15755
name: APT29 thinktanks
description: |
  Original Sigma Rule: https://github.com/Neo23x0/sigma/blob/master/rules/apt/apt_apt29_thinktanks.yml.
  Questions via Twitter: @janvonkirchheim.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents \n| where Timestamp > ago(7d)\n| where ProcessCommandLine has \"-noni -ep bypass $\"\n| top 100 by Timestamp desc \n```"
---

