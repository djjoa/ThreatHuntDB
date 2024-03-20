---
id: 93a4ed6c-83e6-4202-8df4-e340dbd20a38
name: PowerShell downloads (Normalized Process Events)
description: |
  'Finds PowerShell execution events that could involve a download'
requiredDataConnectors: []
tactics:
  - Execution
  - CommandAndControl
query: "```kusto\nimProcessCreate \n  | where Process has_any (\"powershell.exe\", \"powershell_ise.exe\") // perfromance pre-filtering\n  | extend FileName=tostring(split(TargetProcessName, '\\\\')[-1])\n  | where FileName in~ (\"powershell.exe\", \"powershell_ise.exe\")\n  | where CommandLine has_any (\"Net.WebClient\", \"DownloadFile\", \"Invoke-WebRequest\", \"Invoke-Shellcode\", \"http:\", \"https:\")\n  | project TimeGenerated, Dvc, User, ActingProcessName, FileName, CommandLine, EventVendor, EventProduct\n  | top 100 by TimeGenerated\n  | extend timestamp = TimeGenerated\n```"
version: 1.0.1
---

