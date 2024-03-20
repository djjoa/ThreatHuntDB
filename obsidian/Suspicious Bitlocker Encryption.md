---
id: 476c9326-c53d-495c-8a54-c304a43cb446
name: Suspicious Bitlocker Encryption
description: |
  Looks for potential instances of bitlocker modifying registry settings to allow encryption, where it's executed via a .bat file.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Ransomware
query: "```kusto\nDeviceProcessEvents\n| where FileName =~ \"reg.exe\" \n// Search for BitLocker encryption being enabled without the chip\n    and ProcessCommandLine has \"EnableBDEWithNoTPM\"\n    // Using contains due to variant forms of capturing 1: 1, 0x1\n    and (ProcessCommandLine has \"true\" or ProcessCommandLine contains \"1\")\n// Search for this activity being launched by batch scripts, typically as: C:\\Windows\\[name].bat\n| where InitiatingProcessCommandLine has_all (@\"C:\\Windows\\\", \".bat\")\n```"
---

