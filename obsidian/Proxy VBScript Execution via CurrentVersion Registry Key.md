---
id: 3ac1e703-3ed0-45e1-ae1d-0fa60baf99fb
name: Proxy VBScript Execution via CurrentVersion Registry Key
description: |
  'Identifies VBScript proxy execution through a registry key in \Microsoft\Windows\CurrentVersion.'
requiredDataConnectors:
  - connectorId: SecurityEvent
    dataTypes:
      - SecurityEvent
tactics:
  - DefenseEvasion
  - Execution
relevantTechniques:
  - T1059.005
  - T1218.005
query: "```kusto\nSecurityEvent\n| where Process  has_any (\"cmd.exe\", \"powershell.exe\", \"rundll32.exe\", \"AppData\") \nand CommandLine contains \"\\\\Microsoft\\\\Windows\\\\CurrentVersion\"\nand CommandLine has_all (\"Execute\",\"CreateObject\", \"RegRead\")\nor CommandLine has_all (\"vbscript\" ,\"\\\\..\\\\mshtml\" , \"RunHTMLApplication\")\n| project TimeGenerated, Computer, tostring(EventID), ParentProcessName, NewProcessName, CommandLine, SubjectUserName, SourceComputerId, processID=tolong(NewProcessId), parentProcessID=tolong(ProcessId), EventData| order by TimeGenerated\n```"
version: 1.0.0
---

