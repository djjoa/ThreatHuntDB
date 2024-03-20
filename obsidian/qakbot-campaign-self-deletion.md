---
id: 0ec8d8df-2a7f-4cc0-9bd4-64d8f5103e3b
name: qakbot-campaign-self-deletion
description: |
  This query was originally published in the threat analytics report, Qakbot blight lingers, seeds ransomware
  Qakbot is malware that steals login credentials from banking and financial services. It has been deployed against small businesses as well as major corporations. Some outbreaks have involved targeted ransomware campaigns that use a similar set of techniques. Links to related queries are listed under See also.
  The following query detects if an instance of Qakbot has attempted to overwrite its original binary.
  Reference - https://www.microsoft.com/security/blog/2017/11/06/mitigating-and-eliminating-info-stealing-qakbot-and-emotet-in-corporate-networks/
requiredDataConnectors:
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Defense evasion
query: "```kusto\nDeviceProcessEvents \n| where FileName =~ \"ping.exe\"\n| where InitiatingProcessFileName =~ \"cmd.exe\"\n| where InitiatingProcessCommandLine has \"calc.exe\" and\nInitiatingProcessCommandLine has \"-n 6\" \nand InitiatingProcessCommandLine has \"127.0.0.1\"\n| project ProcessCommandLine, InitiatingProcessCommandLine,\nInitiatingProcessParentFileName, DeviceId, Timestamp\n```"
---

