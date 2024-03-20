---
id: 278592b5-612b-48a4-bb38-4c01ff8ee2a5
name: SolarWinds Inventory
description: |
  'Beyond your internal software management systems, it is possible you may not have visibility into your entire footprint of SolarWinds installations. This query helps discover any systems that have SolarWinds processes.'
description-detailed: |
  'Beyond your internal software management systems, it is possible you may not have visibility into your entire footprint of SolarWinds installations. This is intended to help use process exection information to discovery any systems that have SolarWinds processes'
requiredDataConnectors:
  - connectorId: SecurityEvents
    dataTypes:
      - SecurityEvent
  - connectorId: MicrosoftThreatProtection
    dataTypes:
      - DeviceProcessEvents
  - connectorId: WindowsSecurityEvents
    dataTypes:
      - SecurityEvents
  - connectorId: WindowsForwardedEvents
    dataTypes:
      - WindowsEvent
tactics:
  - Execution
relevantTechniques:
  - T1072
tags:
  - Solorigate
  - NOBELIUM
query: "```kusto\n\n(union isfuzzy=true \n( \nSecurityEvent  \n| where EventID == '4688' \n| where tolower(NewProcessName) has 'solarwinds' \n| extend MachineName = Computer , Process = NewProcessName\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account) by Process, Type\n), \n( \nWindowsEvent  \n| where EventID == '4688' and EventData has \"solarwinds\"\n| extend NewProcessName = tostring(EventData.NewProcessName)\n| where tolower(NewProcessName) has 'solarwinds' \n| extend MachineName = Computer , Process = NewProcessName\n| extend Account =  strcat(tostring(EventData.SubjectDomainName),\"\\\\\", tostring(EventData.SubjectUserName))\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account) by Process, Type\n), \n( \nDeviceProcessEvents \n| where tolower(InitiatingProcessFolderPath) has 'solarwinds' \n| extend MachineName = DeviceName , Process = InitiatingProcessFolderPath, Account = AccountName\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account)  by Process, Type\n), \n( \nEvent \n| where Source == \"Microsoft-Windows-Sysmon\" \n| where EventID == 1 \n| extend Image = tostring(parse_json(EventData).[4].[\"#text\"]) \n| where tolower(Image) has 'solarwinds' \n| extend MachineName = Computer , Process = Image, Account = UserName\n| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), MachineCount = dcount(MachineName), AccountCount = dcount(Account), MachineNames = make_set(MachineName), Accounts = make_set(Account)  by Process, Type\n) \n) \n```"
version: 1.0.1
---

