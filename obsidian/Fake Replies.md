---
id: 8c4da386-7a95-4927-b24c-a13137294e0c
name: Fake Replies
description: |
  Use this query to find spoofed reply emails that contain certain keywords in the subject. The emails are also checked for a link to a document in Google Docs.
  These attacks have been observed leading to ransomware
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
      - EmailUrlInfo
tactics:
  - Initial access
  - Ransomware
query: "```kusto\nlet SubjectTerms = pack_array('onus','equired','all','urvey','eb', 'eport','you','nation','me','itting','book','ocument','ill'); \nEmailEvents \n| where EmailDirection == \"Inbound\" \n| where Subject startswith \"RE:\" \n| where Subject has_any(SubjectTerms) \n| join EmailUrlInfo on $left.NetworkMessageId == $right.NetworkMessageId \n| where Url startswith \"https://docs.google.com/document/\" \n```"
---

