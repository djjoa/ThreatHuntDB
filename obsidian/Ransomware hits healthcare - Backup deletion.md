---
id: b0188e2d-734d-4d54-8e70-c4157a195bb1
name: Ransomware hits healthcare - Backup deletion
description: |
  List alerts flagging attempts to delete backup files.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - AlertInfo
      - AlertEvidence
query: "```kusto\nAlertInfo\n| where Timestamp > ago(7d) \n| where Title == \"File backups were deleted\" \n| join AlertEvidence on AlertId \n```"
---

