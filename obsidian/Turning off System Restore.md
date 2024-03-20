---
id: 5de97d18-b12b-4acf-9c3e-c96a67e80312
name: Turning off System Restore
description: |
  This query identifies attempts to stop System Restore and prevent the system from creating restore points, which can be used to recover data encrypted by ransomware
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\nDeviceProcessEvents\n//Pivoting for rundll32  \n| where InitiatingProcessFileName =~ 'rundll32.exe'   \n//Looking for empty command line   \nand InitiatingProcessCommandLine !contains \" \" and InitiatingProcessCommandLine != \"\"  \n//Looking for schtasks.exe as the created process  \nand FileName in~ ('schtasks.exe')  \n//Disabling system restore   \nand ProcessCommandLine has 'Change' and ProcessCommandLine has 'SystemRestore' \nand ProcessCommandLine has 'disable'\n```"
---

