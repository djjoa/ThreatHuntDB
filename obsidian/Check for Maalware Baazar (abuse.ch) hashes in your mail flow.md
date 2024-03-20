---
id: 3dfabb54-3553-47cf-b734-5327e9133874
name: Check for Maalware Baazar (abuse.ch) hashes in your mail flow
description: |
  Check if file hashes published in the recent abuse.ch feed are found in your mail flow scanned by Office 365 ATP.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailAttachmentInfo
tactics:
  - Initial access
  - Malware, component
query: "```kusto\nlet abuse_sha256 = (externaldata(sha256_hash: string )\n[@\"https://bazaar.abuse.ch/export/txt/sha256/recent/\"]\nwith (format=\"txt\"))\n| where sha256_hash !startswith \"#\"\n| project sha256_hash;\nabuse_sha256\n| join (EmailAttachmentInfo \n| where Timestamp > ago(1d) \n) on $left.sha256_hash == $right.SHA256\n| project Timestamp,SenderFromAddress ,RecipientEmailAddress,FileName,FileType,SHA256,ThreatTypes,DetectionMethods\n```"
---

