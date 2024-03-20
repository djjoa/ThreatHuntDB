---
id: 361aa11c-c7ad-4ef0-99fd-2ef52ddd2ba6
name: DLLHost.exe file creation via PowerShell
description: |
  Identify masqueraded DLLHost.exe file created by PowerShell.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Execution
query: "```kusto\nDeviceProcessEvents \n| where InitiatingProcessFileName =~ 'powershell.exe' \n| where InitiatingProcessCommandLine has_all('$file=', 'dllhost.exe', 'Invoke-WebRequest', '-OutFile')\n```"
---

