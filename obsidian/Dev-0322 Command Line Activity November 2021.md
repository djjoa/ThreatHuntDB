---
id: 78fa22f9-0c13-4847-bbe6-6a7aa1b47547
name: Dev-0322 Command Line Activity November 2021
description: |
  'This query hunts for command line activity linked to Dev-0322's compromise of ZOHO ManageEngine ADSelfService Plus software. It focuses on commands used in post-exploitation activity. Hosts with higher risk scores should be prioritized.'
description-detailed: |
  'This hunting query looks for process command line activity related to activity observed by Dev-0322 relating to compromise of systems running the ZOHO ManageEngine ADSelfService Plus software.
    The command lines this query hunts for are used as part of the threat actor's post exploitation activity. Some or all of the commands may be run by the threat actor.
    The risk score associated with each result is based on a number of factors, hosts with higher risk events should be investigated first.'
requiredDataConnectors:
  - connectorId: MicrosoftDefenderAdvancedThreatProtection
    dataTypes:
      - SecurityAlert (MDATP)
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
tactics:
  - Persistence
  - LateralMovement
  - CommandAndControl
relevantTechniques:
  - T1078
  - T1219
  - T1021
query: |-
  ```kusto
  // Look for command lines observed used by the threat actor
  let cmd_lines = dynamic(['regsvr32 /s c:\\windows\\temp\\user64.dll', 'process call  create "cmd /c c:\\windows\\temp\\gac.exe -i c:\\windows\temp\\ScriptModule.dll >c:\\windows\\temp\\tmp.dat"']);
  DeviceProcessEvents
  // Look for static cmd lines and dynamic one using regex
  | where ProcessCommandLine has_any (cmd_lines) or ProcessCommandLine matches regex "save HKLM\\SYSTEM [^ ]*_System.HIV" or ProcessCommandLine matches regex 'cmd.exe /c "wmic /node:[^ ]* process call create "ntdsutil snapshot \\"activate instance ntds\\" create quit quit > c:\\windows\\temp\\nt.dat";'  or InitiatingProcessCommandLine has_any (cmd_lines) or InitiatingProcessCommandLine  matches regex "save HKLM\\SYSTEM [^ ]*_System.HIV" or InitiatingProcessCommandLine  matches regex "save HKLM\\SYSTEM [^ ]*_System.HIV" or ProcessCommandLine matches regex 'cmd.exe /c "wmic /node:[^ ]* process call create "ntdsutil snapshot \\"activate instance ntds\\" create quit quit > c:\\windows\\temp\\nt.dat";'
  | summarize count(), FirstSeen=min(TimeGenerated), LastSeen = max(TimeGenerated) by DeviceId, DeviceName, ProcessCommandLine, AccountName, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessAccountSid, SHA256
  // Base risk score on number of command lines seen for each host
  | extend RiskScore = count_
  // Increase risk score if host has recent security alerts
  | join kind=leftouter (SecurityAlert
  | where ProviderName =~ "MDATP"
  | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
  | mv-expand todynamic(Entities)
  | extend DeviceId = tostring(parse_json(Entities).MdatpDeviceId)
  | where isnotempty(DeviceId)
  // Increase risk score further if alerts relate to malware assocaited with threat actor
  | extend AlertRiskScore = iif(ThreatName has_any ("Zebracon", "Trojan:MSIL/Gacker.A!dha", "Backdoor:MSIL/Kokishell.A!dha"), 1.0, 0.5)) on DeviceId
  | extend AlertRiskScore = iif(isempty(AlertRiskScore), 0.0 , AlertRiskScore)
  // Create aggregate risk score
  | extend RiskScore = RiskScore + AlertRiskScore
  | project-reorder  FirstSeen, LastSeen, RiskScore, DeviceName, DeviceId, ProcessCommandLine, AccountName
  | extend timestamp = FirstSeen, AccountCustomEntity = AccountName, HostCustomEntity = DeviceName
  ```
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
  - entityType: File
    fieldMappings:
      - identifier: Name
        columnName: FileName
  - entityType: FileHash
    fieldMappings:
      - identifier: Value
        columnName: SHA256
---

