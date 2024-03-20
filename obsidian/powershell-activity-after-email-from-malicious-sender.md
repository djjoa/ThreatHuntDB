---
id: 0605673c-8363-40b3-bbe2-ac1a2c17d116
name: powershell-activity-after-email-from-malicious-sender
description: |
  Malicious emails often contain documents and other specially crafted attachments that run PowerShell commands to deliver additional payloads. If you are aware of emails coming from a known malicious sender, you can use this query to list and review PowerShell activities that occurred within 30 minutes after an email was received from the sender .
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - EmailEvents
      - DeviceProcessEvents
tactics:
  - Execution
query: "```kusto\n//Find PowerShell activities right after email was received from malicious sender\nlet x=EmailEvents\n| where SenderFromAddress =~ \"MaliciousSender@example.com\"\n| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, \"@\")[0]);\nx\n| join (\nDeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n//| where InitiatingProcessParentFileName =~ \"outlook.exe\"\n| project TimeProc = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine\n) on AccountName \n| where (TimeProc - TimeEmail) between (0min.. 30min)\n```"
---

