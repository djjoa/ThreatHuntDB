---
id: 44a5c680-d2ac-4bed-8210-c3aafea47308
name: logon-attempts-after-malicious-email
description: |
  This query finds the 10 latest logons performed by email recipients within 30 minutes after they received known malicious emails. You can use this query to check whether the accounts of the email recipients have been compromised.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
      - IdentityLogonEvents
tactics:
  - Credential Access
query: "```kusto\n//Find logons that occurred right after malicious email was received\nlet MaliciousEmail=EmailEvents\n| where ThreatTypes has_cs \"Malware\" \n| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, \"@\")[0]);\nMaliciousEmail\n| join (\nIdentityLogonEvents\n| project LogonTime = Timestamp, AccountName, DeviceName\n) on AccountName \n| where (LogonTime - TimeEmail) between (0min.. 30min)\n| take 10\n```"
---

