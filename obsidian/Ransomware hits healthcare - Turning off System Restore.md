---
id: c6387bdd-c0ee-4b88-bbc2-3897586ecdda
name: Ransomware hits healthcare - Turning off System Restore
description: |
  Find attempts to stop System Restore and.
  Prevent the system from creating restore points.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
query: "```kusto\nDeviceProcessEvents  \n| where Timestamp > ago(7d)  \n// Pivoting for rundll32  \nand InitiatingProcessFileName =~ 'rundll32.exe'   \n// Looking for empty command line   \nand isnotempty(InitiatingProcessCommandLine)  \n// Looking for schtasks.exe as the created process  \nand FileName in~ ('schtasks.exe')  \n// Disabling system restore   \nand ProcessCommandLine has 'Change' and ProcessCommandLine has 'SystemRestore' \nand ProcessCommandLine has 'disable'\n```"
---

