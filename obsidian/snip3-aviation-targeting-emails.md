---
id: cfffcab3-d4c7-4aad-b80d-5f415ef5ac66
name: snip3-aviation-targeting-emails
description: |
  Snip3 is a family of related remote access trojans. Although the malware in this family contain numerous small variations, they all exhibit similar behaviors and techniques.
  The following query looks for keywords observed in emails involved in a Snip3-associated campaign in April and May of 2021. The emails often have an aviation theme, and the campaign primarily targets organizations involved in travel or  aviation. Note that keywords may change overtime. These emails were used to send malicious legitimate hosting provider links that redirected to VBS documents hosting loaders. The loaders initiate RevengeRAT or AsyncRAT downloads that eventually establish persistence on targets and exfiltrate data.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
      - EmailUrlInfo
tactics:
  - Initial access
query: "```kusto\nlet SubjectTerms = \npack_array(\"Cargo Charter\",\"Airbus Meeting\",\"WorldWide Symposium\",\"Airbus Family\",\"Flight Request\",\n\"Advice from NetJets\",\"May/ACMI\",\"AIRCRAFT PRESENTATION\",\"Airworthiness\", \"Air Quote\", \"RFQ #9B17811\");\nEmailEvents\n| where SenderDisplayName has_any(SubjectTerms)\n// Optional Sender restriction for organizations with high FP\n// where SenderIpv4 == \"192.145.239.18\"  \n| where EmailDirection == \"Inbound\"  \n| join EmailUrlInfo on $left.NetworkMessageId == $right.NetworkMessageId\n| where Url has_any(\"drive.google.com\",\"1drv.ms\",\"onedrive.live.com\")\n| take 100\n```"
---

