---
id: 166c732a-a02e-4c7a-a441-cb74fe3c3f2d
name: Use of MSBuild as LOLBin
description: |
  Prior to deploying Macaw ransomware in an organization, the adversary frequently uses MSBuild.exe as a LOLBin to communicate with the C2.
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Command and control
query: "```kusto\nDeviceProcessEvents \n| where InitiatingProcessFileName =~ \"wmiprvse.exe\" \n| where FileName =~ \"msbuild.exe\" and ProcessCommandLine has \"programdata\"\n```"
---

