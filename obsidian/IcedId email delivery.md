---
id: 1d8393fe-e363-40c1-8efb-66cf1ad68a05
name: IcedId email delivery
description: |
  Use this query to locate emails and malicious downloads related to the IcedId activity that can lead to ransomware
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailUrlInfo
      - EmailEvents
tactics:
  - Initial access
  - Ransomware
query: "```kusto\nEmailUrlInfo \n| where Url matches regex @\"\\bsites\\.google\\.com\\/view\\/(?:id)?\\d{9,}\\b\" \n| join EmailEvents on NetworkMessageId // Note: Replace the following subject lines with the one generated by your website's Contact submission form if no results return initially \n| where Subject has_any('Contact Us', 'New Submission', 'Contact Form', 'Form submission')\n```"
---
