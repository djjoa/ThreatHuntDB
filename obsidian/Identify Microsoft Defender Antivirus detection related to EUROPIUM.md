---
id: d02275d6-45ba-4ddc-be90-8fa260aebe55
name: Identify Microsoft Defender Antivirus detection related to EUROPIUM
description: |
  This query looks for Microsoft Defender Antivirus detections related to EUROPIUM actor
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertEvidence
tactics:
  - Impact
query: "```kusto\nlet europium_sigs = dynamic([\"BatRunGoXml\", \"WprJooblash\", \"Win32/Eagle!MSR\", \"Win32/Debitom.A\"]);  \nAlertEvidence \n| where ThreatFamily in~ (europium_sigs) \n| join AlertInfo on AlertId \n| project ThreatFamily, AlertId \n```"
---

