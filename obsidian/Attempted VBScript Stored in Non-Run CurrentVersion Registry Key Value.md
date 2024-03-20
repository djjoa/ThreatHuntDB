---
id: d7233f14-4705-403e-9db9-e0d677c9506b
name: Attempted VBScript Stored in Non-Run CurrentVersion Registry Key Value
description: |
  'Identify potential new registry key name that is a non-autorun and non-run key in the HKLM\Software\Microsoft\Windows\CurrentVersion\ registry key containing VBScript in the key value value.'
requiredDataConnectors:
  - connectorId: SecurityEvent
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
relevantTechniques:
  - T1112
query: "```kusto\nSecurityEvent\n| where ObjectName has \"\\\\CurrentVersion\"\n| where ObjectName !has \"\\\\Run\"\n| where NewValue contains \"RunHTMLApplication\" or \n  NewValue contains \"vbscript\" or \n  NewValue contains \"jscript\" or \n  NewValue contains \"mshtml\" or \n  NewValue contains \"mshtml,\" or \n  NewValue contains \"mshtml \" or \n  NewValue contains \"Execute(\" or \n  NewValue contains \"CreateObject\" or \n  NewValue contains \"RegRead\" or \n  NewValue contains \"window.close\"\n| project TimeGenerated, Computer, Process, ObjectName, ObjectValueName, NewValue, OldValue, SubjectUserName, NewProcessId, SourceComputerId\n| order by TimeGenerated\n```"
version: 1.0.0
---

