---
id: 3c82774a-df78-44eb-9ab3-13ef37c63ae4
name: Sticky Keys
description: |
  A technique used in numerous ransomware attacks is a Sticky Keys hijack for privilege escalation/persistence. Surface realted alerts with this query.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
tactics:
  - Ransomware
query: "```kusto\n// Checks for possible hijacking of Sticky Keys feature \nAlertInfo | where Title == \"Sticky Keys binary hijack detected\"\n```"
---

