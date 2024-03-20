---
id: f4c234fd-2889-41b6-ad4b-df257adf882b
name: turn-off-system-restore
description: |
  This query was originally published in the threat analytics report, Ransomware continues to hit healthcare, critical services. There is also a related blog.
  In April of 2020, security researchers observed multiple ransomware campaigns using the same set of techniques.
  The following query detects attempts to stop System Restore, which would prevent the user from recovering data by going back to a restore point.
  The See also section below lists more queries related to techniques shared by these campaigns.
  Reference - https://www.microsoft.com/security/blog/2020/04/28/ransomware-groups-continue-to-target-healthcare-critical-services-heres-how-to-reduce-risk/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense evasion
  - Impact
query: "```kusto\nDeviceProcessEvents  \n| where Timestamp > ago(7d)  \n//Pivoting for rundll32  \nand InitiatingProcessFileName =~ 'rundll32.exe'   \n//Looking for empty command line   \nand InitiatingProcessCommandLine !contains \" \" and InitiatingProcessCommandLine != \"\"  \n//Looking for schtasks.exe as the created process  \nand FileName in~ ('schtasks.exe')  \n//Disabling system restore   \nand ProcessCommandLine has 'Change' and ProcessCommandLine has 'SystemRestore' \nand ProcessCommandLine has 'disable'\n```"
---

