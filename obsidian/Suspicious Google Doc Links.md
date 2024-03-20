---
id: 5b94411c-9311-48cd-8f7f-e35b42174e2d
name: Suspicious Google Doc Links
description: |
  Use this query to find emails with message IDs that resemble IDs used in known attack emails and contain a link a document in Google Docs. These behaviors have
  been observed leading to ransomware attacks.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailUrlInfo
      - EmailEvents
tactics:
  - Initial access
  - Ransomware
query: "```kusto\nEmailUrlInfo \n| where Url startswith \"https://docs.google.com/document/\" \n| join (EmailEvents \n| where EmailDirection == \"Inbound\" \n| where InternetMessageId matches regex \"\\\\<\\\\w{ 38,42} \\\\@\") on NetworkMessageId \n```"
---

